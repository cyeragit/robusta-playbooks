from robusta.api import (
    ActionParams,
    Finding,
    FindingSeverity,
    FindingSubject,
    FindingSubjectType,
    PodEvent,
    action,
)


class DeploymentOOMParams(ActionParams):
    """
    :var title: Finding title (supports $name, $namespace, $labels.X templating)
    :var aggregation_key: Key for grouping alerts
    """
    title: str = "Deployment OOM - $labels.service"
    aggregation_key: str = "DeploymentOOM"


@action
def deployment_oom_finding(event: PodEvent, params: DeploymentOOMParams):
    """
    Create an OOM finding grouped by deployment instead of pod.
    Uses the 'service' label as the deployment identifier.
    """
    pod = event.get_pod()
    if not pod:
        return

    labels = pod.metadata.labels or {}

    # Get deployment name from labels (try common patterns)
    deployment_name = labels.get("service") or labels.get("app") or pod.metadata.name

    # Create subject with deployment name instead of pod name
    subject = FindingSubject(
        name=deployment_name,
        subject_type=FindingSubjectType.TYPE_DEPLOYMENT,
        namespace=pod.metadata.namespace,
        labels=labels,
    )

    # Simple title templating
    title = params.title
    title = title.replace("$name", pod.metadata.name)
    title = title.replace("$namespace", pod.metadata.namespace)
    for key, value in labels.items():
        title = title.replace(f"$labels.{key}", str(value))

    event.add_finding(
        Finding(
            title=title,
            aggregation_key=params.aggregation_key,
            severity=FindingSeverity.HIGH,
            subject=subject,
            source=event.get_source(),
        )
    )

