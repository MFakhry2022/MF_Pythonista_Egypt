# Generated by Django 4.2.7 on 2023-11-10 12:54

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("invoice", "0007_process_minings"),
    ]

    operations = [
        migrations.CreateModel(
            name="Pythonestas",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "Pythonestas",
            },
        ),
    ]
