# Contributing to Caulk

Thank you for contributing to Caulk! We welcome improvements, rule additions, bug fixes, and documentation updates.

---

## 1. Development Setup

Caulk requires **Python 3.11** or newer.

1. Clone the repository:
   ```bash
   git clone https://github.com/kunal-gswm/caulk.git
   cd caulk
   ```

2. Create and activate a virtual environment:
   ```bash
   # Using standard venv
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate

   # Or using uv
   uv venv .venv --python 3.12
   .venv\Scripts\activate
   ```

3. Install in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   # Or with uv:
   uv pip install -e ".[dev]"
   ```

---

## 2. Quality Gates & Testing

Before submitting a Pull Request, all tests, linting, and type checks must pass cleanly.

1. **Run the automated test suite:**
   ```bash
   pytest
   ```

2. **Check test coverage:**
   ```bash
   pytest --cov=caulk --cov-report=term-missing
   ```

3. **Run Ruff linter and formatter checks:**
   ```bash
   ruff check .
   ruff format --check .
   ```

4. **Run Mypy static type checking:**
   ```bash
   mypy src
   ```

---

## 3. Pull Request Guidelines

- Branch names should be descriptive (e.g. `feat/new-secret-rule`, `fix/traversal-guard`).
- All new rules must include positive and negative test cases.
- Synthetic fixtures must never contain real production secrets or personal data.
- Ensure all CI workflow checks are green.
