# Generated by Django 5.1.3 on 2024-11-11 13:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0007_remove_details_processor_cores_details_cpu_cores_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_active',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='details',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to='images'),
        ),
        migrations.AlterField(
            model_name='item',
            name='slug',
            field=models.SlugField(blank=True, max_length=64, unique=True),
        ),
        migrations.AlterField(
            model_name='order',
            name='state',
            field=models.CharField(choices=[('cart', 'In cart'), ('new', 'New'), ('packing', 'Packing'), ('packed', 'Packed'), ('delivering', 'Delivering'), ('delivered', 'Delivered'), ('сanceled', 'Сanceled'), ('received', 'Received')], default='cart'),
        ),
    ]
