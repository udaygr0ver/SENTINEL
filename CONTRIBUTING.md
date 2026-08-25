# Contributing to SENTINEL

Thank you for your interest in improving SENTINEL!

## Pull Request Process

1. Ensure any new dependencies are added to `requirements.txt`.
2. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations, and container parameters.
3. Ensure the test suite passes by running `pytest tests/`.
4. You may merge the Pull Request in once you have the sign-off of the maintainer.

## Adding Parsers
If you add a new log parser, please include a mocked test case in `tests/` to guarantee deterministic behavior in the CI pipeline.
