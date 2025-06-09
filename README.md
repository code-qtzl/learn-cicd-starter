![code coverage badge](https://github.com/code-qtzl/learn-cicd-starter/actions/workflows/ci.yml/badge.svg)

# learn-cicd-starter (Notely)

This repo contains the starter code for the "Notely" application for the "Learn CICD" course on [Boot.dev](https://boot.dev).

## Local Development

Make sure you're on Go version 1.22+.

Create a `.env` file in the root of the project with the following contents:

```bash
PORT="8080"
```

Run the server:

```bash
go build -o notely && ./notely
```

_Starting the server in non-database mode._ It will serve a webpage at `http://localhost:8080`.

You do _not_ need to set up a database or any interactivity on the webpage yet. Instructions for that will come later in the course!

[//]: <> (making a comment.)

## Recap

Recap of CRUD app accomplishments

-   Set up a continuous integration pipeline with GitHub Actions that ensures new PRs pass certain checks before they are merged to `main`:
    -   Unit tests pass
    -   Formatting checks pass
    -   Linting checks pass
    -   Security checks pass
-   Configured a cloud-based SQLite database hosted on [Turso](https://turso.tech/)
-   Set up a continuous deployment pipeline with GitHub Actions that does the following whenever changes are merged into `main`:
    -   Builds a new server binary
    -   Builds a new Docker image for the server
    -   Pushes the Docker image to the Google Artifact Registry
    -   Deploys a new Cloud Run revision with the new image and serves the app to the public internet
