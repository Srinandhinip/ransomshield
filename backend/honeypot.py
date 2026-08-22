from backend.config import HONEYPOT_DIR


HONEYPOT_FILES = [
    "financial_records.txt",
    "password_backup.txt",
    "employee_salary_data.txt",
    "confidential_project.txt",
    "bank_information.txt"
]


def create_honeypots():

    HONEYPOT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    for filename in HONEYPOT_FILES:

        file_path = (
            HONEYPOT_DIR / filename
        )

        if not file_path.exists():

            file_path.write_text(
                "RansomShield Security Test File\n"
                "This file is a controlled honeypot.\n"
                "Unauthorized modification should trigger detection.\n"
            )

            print(
                f"[HONEYPOT CREATED] {file_path}"
            )


def list_honeypots():
    """Return honeypot filenames with their current existence state."""

    honeypots = []

    for filename in HONEYPOT_FILES:

        file_path = HONEYPOT_DIR / filename

        honeypots.append({
            "filename": filename,
            "path": str(file_path),
            "exists": file_path.exists()
        })

    return honeypots


if __name__ == "__main__":

    print("Creating RansomShield honeypots...")
    print()

    create_honeypots()

    print()
    print("Honeypot deployment complete.")
