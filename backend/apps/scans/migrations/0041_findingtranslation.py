from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0040_agentfindingstate"),
    ]

    operations = [
        migrations.CreateModel(
            name="FindingTranslation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_hash", models.CharField(max_length=64)),
                ("target_lang", models.CharField(default="zh-Hant", max_length=16)),
                ("payload", models.JSONField(default=dict)),
                ("model", models.CharField(blank=True, default="", max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddConstraint(
            model_name="findingtranslation",
            constraint=models.UniqueConstraint(fields=("source_hash", "target_lang"), name="unique_finding_translation"),
        ),
    ]
