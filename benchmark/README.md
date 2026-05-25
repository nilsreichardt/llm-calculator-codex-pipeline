# Benchmark

# Environment

* Codex Version 26.422.71525 (2210)
* Model: GPT-5.5
* Intelligence: Extra High
* Speed: Standard
* Permissions Mode: Full access

## Prompt

Used the following initial prompt

> Add a CI/CD pipeline using GitHub Actions to this project that runs the E2E tests. Also external contributors with fork pull requests should be able to run the pipeline and receive quick feedback about their changes.

Follow up message after Codex failed to follow the instructions:

> OPENAI_API_KEY isn't available for fork pull requests which is why the e2e tests get skips. This was not my requirement. Also for fork pull request it should run the e2e tests with a real OpenAI API key.

