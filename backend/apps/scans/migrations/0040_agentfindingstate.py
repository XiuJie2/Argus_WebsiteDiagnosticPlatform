from django.conf import settings
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("scans", "0039_scanjob_agent_focus"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentFindingState",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("origin", models.CharField(db_index=True, max_length=255)),
                ("identity", models.CharField(max_length=512)),
                ("title", models.CharField(blank=True, default="", max_length=255)),
                ("severity", models.CharField(blank=True, default="", max_length=16)),
                ("miss_streak", models.PositiveIntegerField(default=0)),
                ("resolved", models.BooleanField(default=False)),
                ("resolved_scan_id", models.IntegerField(blank=True, null=True)),
                ("first_seen_scan_id", models.IntegerField(blank=True, null=True)),
                ("last_confirmed_scan_id", models.IntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="agent_finding_states", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddConstraint(
            model_name="agentfindingstate",
            constraint=models.UniqueConstraint(fields=("user", "origin", "identity"), name="unique_agent_finding_state"),
        ),
        migrations.AddIndex(
            model_name="agentfindingstate",
            index=models.Index(fields=["user", "origin", "resolved"], name="scans_afs_usr_org_res_idx"),
        ),
    ]
