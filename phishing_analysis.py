
# Project 3: Phishing Awareness Analysis
# Cyber Security Project

# List of sample phishing messages
messages = [
    {
        "title": "Bank Account Suspension Email",
        "message": """
        Dear Customer,

        We noticed suspicious activity on your bank account.
        Click the link below immediately to verify your account:

        http://secure-bank-login.verify-user.ru

        Failure to verify within 24 hours will result in account closure.
        """,
    },

    {
        "title": "Fake Prize SMS",
        "message": """
        Congratulations! You have won an iPhone 17.

        Claim your reward now:
        http://free-prize-claim.xyz

        Offer expires today!
        """,
    },

    {
        "title": "Netflix Payment Scam",
        "message": """
        From: netflix-support@gmail.com

        Your Netflix payment failed.
        Update your payment information immediately:

        http://netflix-account-update.fake-login.com
        """,
    }
]

# Common phishing keywords
suspicious_keywords = [
    "urgent",
    "immediately",
    "verify",
    "suspended",
    "won",
    "claim",
    "payment failed",
    "click",
    "account closure",
    "reward"
]

# Suspicious domains
suspicious_domains = [
    ".ru",
    ".xyz",
    "fake-login",
    "verify-user"
]


# Function to analyze phishing messages
def analyze_message(title, message):

    print("\n===================================")
    print("Analyzing:", title)
    print("===================================")

    red_flags = []

    # Convert message to lowercase
    lower_message = message.lower()

    # Check for suspicious keywords
    for keyword in suspicious_keywords:
        if keyword in lower_message:
            red_flags.append(f"Suspicious keyword found: '{keyword}'")

    # Check for suspicious domains
    for domain in suspicious_domains:
        if domain in lower_message:
            red_flags.append(f"Suspicious link/domain found: '{domain}'")

    # Check for HTTP links
    if "http://" in lower_message:
        red_flags.append("Unsafe link detected (HTTP instead of HTTPS)")

    # Check for generic greetings
    if "dear customer" in lower_message:
        red_flags.append("Generic greeting used")

    # Check for Gmail pretending to be company
    if "@gmail.com" in lower_message:
        red_flags.append("Unprofessional sender email address")

    # Display results
    print("\nMessage:")
    print(message)

    print("\nRed Flags Found:")
    for flag in red_flags:
        print("-", flag)

    # Final safety warning
    if len(red_flags) > 0:
        print("\nResult: This message is likely a PHISHING ATTEMPT.")
    else:
        print("\nResult: No major phishing indicators found.")


# Run analysis for all messages
for item in messages:
    analyze_message(item["title"], item["message"])

# End of Program