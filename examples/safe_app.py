"""Example of a secure LLM-powered app."""

import os
from openai import OpenAI

# Good: API key from environment
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Good: System prompt without secrecy reliance
SYSTEM_PROMPT = """You are a helpful coding assistant.
Respond only with valid Python code.
Do not include markdown formatting."""


def validate_output(text: str) -> str:
    """Validate and sanitize LLM output."""
    # Strip any non-printable characters
    text = "".join(c for c in text if c.isprintable() or c in "\n\t")
    # Limit length
    if len(text) > 10000:
        text = text[:10000]
    return text


def generate_code(description: str) -> str:
    """Generate code safely from a description."""
    # Good: User input is in a separate message, not formatted into system prompt
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": description},  # Separate message
        ],
        max_tokens=2000,  # Good: Limit output
        temperature=0.1,  # Good: Lower temperature for code
    )
    
    result = response.choices[0].message.content
    
    # Good: Validate output before returning
    result = validate_output(result)
    
    # Good: Not executing the output, just returning it
    return result


def main():
    user_input = input("Describe what you want: ")
    code = generate_code(user_input)
    print(f"Generated code:\n{code}")


if __name__ == "__main__":
    main()
