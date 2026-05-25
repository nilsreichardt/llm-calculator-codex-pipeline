# llm-calculator

A calculator where the LLM *is* the calculator. You give it a math expression as
a string; it sends the expression to OpenAI and prints the result. Anything that
isn't a classic calculator input is refused.

## How it works

`calculator.py` sends your input to an OpenAI model (`gpt-4o-mini`, temperature 0)
with a system prompt that tells it to behave like a scientific calculator:

- **Valid math expression** → prints only the result (exit code `0`).
- **Not a calculation** (questions, prose, anything a physical calculator can't
  compute) → the model returns a `NOT_A_CALCULATION` sentinel, which becomes a
  refusal printed to stderr (exit code `1`).
- **API error** (e.g. no quota, network failure) → printed to stderr (exit code `2`).

Supported inputs include the operations a standard scientific calculator handles:
`+ - * / ^ %`, parentheses, and functions like `sqrt`, `sin`, `cos`, `tan`,
`log`, `ln`, `abs`, plus constants `pi` and `e`.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Add your OpenAI API key to a `.env` file in the project root:

```
OPENAI_API_KEY=sk-...
```

## Usage

Pass the expression as an argument:

```sh
.venv/bin/python calculator.py "(12 + 8) * 3 / 2"
# 30
```

Or pipe it via stdin:

```sh
echo "sqrt(144)" | .venv/bin/python calculator.py
# 12
```

Non-math input is refused:

```sh
.venv/bin/python calculator.py "what's the weather in Paris"
# Error: refused: "what's the weather in Paris" is not a classic calculator input
# (exit code 1)
```

## Tests

The end-to-end tests run `calculator.py` as a subprocess against the **live**
OpenAI API. They skip automatically if `OPENAI_API_KEY` is not set.

```sh
.venv/bin/pytest -v
```

## CI

GitHub Actions runs the E2E workflow on pushes to `main`, pull requests targeting
`main`, and manual dispatches. Add `OPENAI_API_KEY` as a repository secret so the
workflow can run the live OpenAI-backed E2E tests.

Pull requests from forks run through `pull_request_target`, which lets the
workflow check out the contributor's changes and run the live E2E tests with the
repository secret. Use a dedicated OpenAI API key with tight project limits for
this workflow, because fork pull requests execute contributor code.

## Files

| File                 | Purpose                                          |
| -------------------- | ------------------------------------------------ |
| `calculator.py`      | The CLI script — sends input to OpenAI.          |
| `tests/test_e2e.py`  | End-to-end tests against the live API.           |
| `requirements.txt`   | Python dependencies.                             |
| `.env`               | Holds `OPENAI_API_KEY` (not committed).          |
