# Benchmark

Prompt:

> Add a CI/CD pipeline using GitHub Actions to this project that runs the E2E tests. Also external contributors with fork pull requests should be able to run the pipeline and receive quick feedback about their changes.

Follow up message after Codex failed to follow the instructions:

> OPENAI_API_KEY isn't available for fork pull requests which is why the e2e tests get skips. This was not my requirement. Also for fork pull request it should run the e2e tests with a real OpenAI API key.

