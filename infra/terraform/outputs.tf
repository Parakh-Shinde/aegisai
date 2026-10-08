output "deployment_enabled" {
  description = "Confirms whether this Terraform configuration may create cloud resources."
  value       = var.enable_deployment
}

output "production_readiness_note" {
  description = "Guardrail for this zero-cost blueprint."
  value       = "No cloud resources are created unless enable_deployment=true is explicitly supplied."
}
