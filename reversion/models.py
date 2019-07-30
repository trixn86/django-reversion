from collections import defaultdict
from itertools import chain, groupby

from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres.fields import JSONField
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.base import DeserializationError
from django.db import IntegrityError, models, router, transaction
from django.db.models.deletion import Collector
from django.db.models.functions import Cast
from django.utils.encoding import force_text
from django.utils.functional import cached_property
from django.utils.translation import ugettext
from django.utils.translation import ugettext_lazy as _

from reversion.errors import RevertError
from reversion.revisions import _follow_relations_recursive, _get_content_type, _get_options


__all__ = [
    'Revision',
    'Version',
]


def _safe_revert(versions):
    unreverted_versions = []

    for version in versions:
        try:
            with transaction.atomic(using=version.db):
                version.revert()
        except (IntegrityError, ObjectDoesNotExist):
            unreverted_versions.append(version)

    if len(unreverted_versions) == len(versions):
        raise RevertError(ugettext('Could not save %(object_repr)s version - missing dependency.') % {
            'object_repr': unreverted_versions[0],
        })

    if unreverted_versions:
        _safe_revert(unreverted_versions)


class Revision(models.Model):

    """A group of related serialized versions."""

    date_created = models.DateTimeField(
        db_index=True,
        verbose_name=_('date created'),
        help_text=_('The date and time this revision was created.'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        verbose_name=_('user'),
        help_text=_('The user who created this revision.'),
    )

    comment = models.TextField(
        blank=True,
        verbose_name=_('comment'),
        help_text=_('A text comment on this revision.'),
    )

    class Meta:
        app_label = 'reversion'
        ordering = ('-pk',)

    def __str__(self):
        return ', '.join(force_text(version) for version in self.versions.all())

    def get_comment(self):
        try:
            LogEntry = apps.get_model('admin.LogEntry')
            return LogEntry(change_message=self.comment).get_change_message()
        except LookupError:
            return self.comment

    def revert(self, delete=False):
        # Group the models by the database of the serialized model.
        versions_by_db = defaultdict(list)

        for version in self.versions.iterator():
            versions_by_db[version.db].append(version)

        # For each db, perform a separate atomic revert.
        for version_db, versions in versions_by_db.items():
            with transaction.atomic(using=version_db):
                # Optionally delete objects no longer in the current revision.
                if delete:
                    # Get a set of all objects in this revision.
                    old_revision = set()

                    for version in versions:
                        model = version._model
                        try:
                            # Load the model instance from the same DB as it was saved under.
                            old_revision.add(model._default_manager.using(version.db).get(pk=version.object_id))
                        except model.DoesNotExist:
                            pass

                    # Calculate the set of all objects that are in the revision now.
                    current_revision = chain.from_iterable(
                        _follow_relations_recursive(obj)
                        for obj in old_revision
                    )

                    # Delete objects that are no longer in the current revision.
                    collector = Collector(using=version_db)
                    new_objs = [item for item in current_revision if item not in old_revision]

                    for model, group in groupby(new_objs, type):
                        collector.collect(list(group))
                    collector.delete()

                # Attempt to revert all revisions.
                _safe_revert(versions)


class VersionQuerySet(models.QuerySet):

    def get_for_model(self, model, model_db=None):
        model_db = model_db or router.db_for_write(model)
        content_type = _get_content_type(model, self.db)
        return self.filter(content_type=content_type, db=model_db)

    def get_for_object_reference(self, model, object_id, model_db=None):
        return self.get_for_model(model, model_db=model_db).filter(object_id=object_id)

    def get_for_object(self, obj, model_db=None):
        return self.get_for_object_reference(obj.__class__, obj.pk, model_db=model_db)

    def get_deleted(self, model, model_db=None):
        model_db = model_db or router.db_for_write(model)

        if self.db == model_db:
            model_qs = (
                model._default_manager
                .using(model_db)
                .annotate(_pk_to_object_id=Cast('pk', Version._meta.get_field('object_id')))
                .filter(_pk_to_object_id=models.OuterRef('object_id'))
            )
            subquery = (
                self.get_for_model(model, model_db=model_db)
                .annotate(pk_not_exists=~models.Exists(model_qs))
                .filter(pk_not_exists=True)
                .values('object_id')
                .annotate(latest_pk=models.Max('pk'))
                .values('latest_pk')
            )
        else:
            # We have to use a slow subquery.
            existing_pks = model._default_manager.using(model_db).values_list('pk', flat=True).order_by().iterator()

            subquery = self.get_for_model(model, model_db=model_db).exclude(
                object_id__in=list(existing_pks),
            ).values_list('object_id').annotate(
                latest_pk=models.Max('pk')
            ).order_by().values_list('latest_pk', flat=True)

        # Perform the subquery.
        return self.filter(pk__in=subquery)

    def get_unique(self):
        last_key = None

        for version in self.iterator():
            key = (version.object_id, version.content_type_id, version.db, version._local_field_dict)

            if last_key != key:
                yield version

            last_key = key


class Version(models.Model):

    """A saved version of a database model."""

    TYPE_INITIAL = 'initial'
    TYPE_CREATE = 'create'
    TYPE_UPDATE = 'update'
    TYPE_DELETE = 'delete'
    TYPE_REVERT = 'revert'

    TYPE_CHOICES = (
        (TYPE_INITIAL, _('initial')),
        (TYPE_CREATE, _('create')),
        (TYPE_UPDATE, _('update')),
        (TYPE_DELETE, _('delete')),
        (TYPE_REVERT, _('revert')),
    )

    revision = models.ForeignKey(
        Revision,
        verbose_name=_('reversion'),
        related_name='versions',
        on_delete=models.CASCADE,
        help_text=_('The revision that contains this version.'),
    )

    type = models.CharField(_('type'), max_length=max(map(len, dict(TYPE_CHOICES))), choices=TYPE_CHOICES)

    object_id = models.CharField(
        _('object id'),
        max_length=191,
        help_text=_('Primary key of the model under version control.'),
    )

    content_type = models.ForeignKey(
        ContentType,
        verbose_name=_('content type'),
        on_delete=models.CASCADE,
        help_text=_('Content type of the model under version control.'),
    )

    # A link to the current instance, not the version stored in this Version!
    object = GenericForeignKey()

    db = models.CharField(
        _('database'),
        max_length=191,
        help_text=_('The database the model under version control is stored in.'),
    )

    data = JSONField(
        _('data'),
        help_text=_('The serialized form of this version of the model.'),
    )

    object_repr = models.TextField(
        help_text=_('A string representation of the object.'),
    )

    objects = VersionQuerySet.as_manager()

    class Meta:
        verbose_name = _('Version')
        verbose_name_plural = _('Versions')
        app_label = 'reversion'
        unique_together = (
            ('db', 'content_type', 'object_id', 'revision'),
        )
        ordering = ('-pk',)

    def __str__(self):
        return self.object_repr

    @property
    def _content_type(self):
        return ContentType.objects.db_manager(self._state.db).get_for_id(self.content_type_id)

    @property
    def _model(self):
        return self._content_type.model_class()

    @cached_property
    def _object_version(self):
        try:
            return list(serializers.deserialize('python', self.data, ignorenonexistent=True))[0]
        except DeserializationError:
            raise RevertError(ugettext('Could not load %(object_repr)s version - incompatible version data.') % {
                'object_repr': self.object_repr,
            })

    @cached_property
    def _local_field_dict(self):
        """
        A dictionary mapping field names to field values in this version
        of the model.

        Parent links of inherited multi-table models will not be followed.
        """

        version_options = _get_options(self._model)
        object_version = self._object_version
        obj = object_version.object
        model = self._model
        field_dict = {}

        for field_name in version_options.fields:
            field = model._meta.get_field(field_name)

            if isinstance(field, models.ManyToManyField):
                # M2M fields with a custom through are not stored in m2m_data, but as a separate model.
                if object_version.m2m_data and field.attname in object_version.m2m_data:
                    field_dict[field.attname] = object_version.m2m_data[field.attname]
            else:
                field_dict[field.attname] = getattr(obj, field.attname)

        return field_dict

    @cached_property
    def field_dict(self):
        """
        A dictionary mapping field names to field values in this version
        of the model.

        This method will follow parent links, if present.
        """

        field_dict = self._local_field_dict

        # Add parent data.
        for parent_model, field in self._model._meta.concrete_model._meta.parents.items():
            content_type = _get_content_type(parent_model, self._state.db)
            parent_id = field_dict[field.attname]
            parent_version = self.revision.versions.get(
                content_type=content_type,
                object_id=parent_id,
                db=self.db,
            )
            field_dict.update(parent_version.field_dict)

        return field_dict

    def revert(self):
        self._object_version.save(using=self.db)


class _Str(models.Func):

    """Casts a value to the database's text type."""

    function = 'CAST'
    template = '%(function)s(%(expressions)s as %(db_type)s)'

    def __init__(self, expression):
        super(_Str, self).__init__(expression, output_field=models.TextField())

    def as_sql(self, compiler, connection):
        self.extra['db_type'] = self.output_field.db_type(connection)
        return super(_Str, self).as_sql(compiler, connection)


def _safe_subquery(method, left_query, left_field_name, right_subquery, right_field_name):
    right_subquery = right_subquery.order_by().values_list(right_field_name, flat=True)
    left_field = left_query.model._meta.get_field(left_field_name)
    right_field = right_subquery.model._meta.get_field(right_field_name)

    # If the databases don't match, we have to do it in-memory.
    is_different_db = left_query.db != right_subquery.db
    is_different_type = left_field.get_internal_type() != right_field.get_internal_type()

    if is_different_db or is_different_type:
        return getattr(left_query, method)(**{
            '{}__in'.format(left_field_name): list(right_subquery.iterator()),
        })
    else:
        # If the left hand side is not a text field, we need to cast it.
        if not isinstance(left_field, (models.CharField, models.TextField)):
            left_field_name_str = '{}_str'.format(left_field_name)
            left_query = left_query.annotate(**{
                left_field_name_str: _Str(left_field_name),
            })
            left_field_name = left_field_name_str

        # If the right hand side is not a text field, we need to cast it.
        if not isinstance(right_field, (models.CharField, models.TextField)):
            right_field_name_str = '{}_str'.format(right_field_name)
            right_subquery = right_subquery.annotate(**{
                right_field_name_str: _Str(right_field_name),
            }).values_list(right_field_name_str, flat=True)
            right_field_name = right_field_name_str

        # Use Exists if running on the same DB, it is much much faster
        exist_annotation_name = '{}_annotation_str'.format(right_subquery.model._meta.db_table)
        right_subquery = right_subquery.filter(**{right_field_name: models.OuterRef(left_field_name)})
        left_query = left_query.annotate(**{exist_annotation_name: models.Exists(right_subquery)})
        return getattr(left_query, method)(**{exist_annotation_name: True})
