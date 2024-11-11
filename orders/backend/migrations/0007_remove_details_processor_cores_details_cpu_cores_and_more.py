# Generated by Django 5.1.3 on 2024-11-11 10:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0006_alter_address_apartment'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='details',
            name='processor_cores',
        ),
        migrations.AddField(
            model_name='details',
            name='cpu_cores',
            field=models.PositiveSmallIntegerField(blank=True, default=1, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='battery',
            field=models.PositiveSmallIntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='camera_back',
            field=models.DecimalField(blank=True, decimal_places=1, max_digits=3, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='camera_front',
            field=models.DecimalField(blank=True, decimal_places=1, max_digits=3, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='color',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='display_diagonal',
            field=models.DecimalField(blank=True, decimal_places=2, max_digits=4, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='display_resolution',
            field=models.CharField(blank=True, max_length=24, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='memory',
            field=models.PositiveSmallIntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='details',
            name='year',
            field=models.PositiveSmallIntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='item',
            name='slug',
            field=models.SlugField(max_length=64, unique=True),
        ),
    ]
