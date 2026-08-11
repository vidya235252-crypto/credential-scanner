REMEDIATION_RECOMMENDATIONS = {
    "AWS Access Key ID": [
        "Rotate the credential in AWS IAM immediately.",
        "Revoke the exposed access key.",
        "Move credentials to environment variables or a secrets manager.",
        "Remove the credential from repository history."
    ],
    "AWS Secret Key": [
        "Rotate the credential in AWS IAM immediately.",
        "Revoke the exposed secret key.",
        "Move credentials to environment variables or a secrets manager.",
        "Remove the credential from repository history."
    ],
    "Generic API Key": [
        "Revoke and regenerate the key with the issuing provider.",
        "Move the key to environment variables or a secrets manager.",
        "Remove the key from repository history.",
        "Check provider logs for unauthorized usage."
    ],
    "Private Key Header": [
        "Revoke the key and issue a new key pair immediately.",
        "Remove it from repository history — treat it as fully compromised.",
        "Update any services or servers that trusted this key."
    ],
    "Slack Token": [
        "Revoke the token in Slack's app management settings.",
        "Generate a new token and store it in environment variables.",
        "Review Slack's audit log for unauthorized activity.",
        "Remove the token from repository history."
    ],
    "High entropy string": [
        "Manually verify whether this value is a real credential.",
        "If real, rotate/revoke it and move it to a secrets manager.",
        "If a false positive, consider adding it to an ignore list."
    ]
}

DEFAULT_RECOMMENDATIONS = [
    "Manually review this finding to confirm whether it's a real credential.",
    "If confirmed, rotate/revoke it and move it out of source control.",
    "Remove the value from repository history if it was ever committed."
]


def get_recommendations(finding_type):
    return REMEDIATION_RECOMMENDATIONS.get(finding_type, DEFAULT_RECOMMENDATIONS)


if __name__ == "__main__":
    print(get_recommendations("AWS Access Key ID"))
    print(get_recommendations("Some New Pattern Type Not Yet Added"))