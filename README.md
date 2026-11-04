# J Security Scanner

Netlify static dashboard with a Netlify Function for bounded HTML crawling and form discovery.

## Deploy
1. Upload this folder to a Git repository.
2. Import the repository in Netlify.
3. In Site configuration > Environment variables, set `LAB_ALLOWED_HOSTS` to a comma-separated list of exact lab hostnames, for example `lab.example.com`.
4. Deploy.

The function requires HTTPS and only crawls the exact configured hostname. SQLi, XSS, and IDOR are reported as not tested; this starter does not send exploit payloads.
