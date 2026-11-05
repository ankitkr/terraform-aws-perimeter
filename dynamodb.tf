# One table: the configuration (written here), one item per endpoint with its last verdicts and
# scan, and markers for the tripwire events already alerted on, which expire after a day.
resource "aws_dynamodb_table" "this" {
  name         = var.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "expires"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = var.tags
}

resource "aws_dynamodb_table_item" "config" {
  table_name = aws_dynamodb_table.this.name
  hash_key   = aws_dynamodb_table.this.hash_key

  item = jsonencode({
    pk   = { S = "config" }
    json = { S = jsonencode(local.config) }
  })

  lifecycle {
    precondition {
      condition     = !contains(values(var.accounts), local.account_id)
      error_message = "This account (${local.account_id}) is always scanned as account_name; remove it from accounts."
    }
  }
}
