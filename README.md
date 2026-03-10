# Sloth Jobs: Your Ironman Suit for Job Hunting


[![Stars](https://img.shields.io/github/stars/coreymaypray/sloth-jobs?style=social)](https://github.com/coreymaypray/sloth-jobs)
[![GHCR](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker&logoColor=white)](https://github.com/coreymaypray/sloth-jobs/pkgs/container/sloth-jobs)
[![Release](https://github.com/coreymaypray/sloth-jobs/actions/workflows/ghcr.yml/badge.svg)](https://github.com/coreymaypray/sloth-jobs/actions/workflows/ghcr.yml)


Scrapes major job boards (LinkedIn, Indeed, Glassdoor & more), AI-scores suitability, tailors resumes (RxResume), and tracks application emails automatically.

You still apply to every job yourself. Sloth Jobs just finds jobs, makes sure you're applying to the right ones with a tailored CV, and not losing track of where you're at.

<img width="1200" height="600" alt="image" src="https://github.com/user-attachments/assets/7328102a-530d-4bd0-af0b-ce8a1b864f41" />


Self-hosted. Docker-based. Forked from [DaKheera47/job-ops](https://github.com/DaKheera47/job-ops).

## 40s Demo: Crawl → Score → PDF → Track

<details>
<summary>
Pipeline Demo
</summary>

  https://github.com/user-attachments/assets/5b9157a9-13b0-4ec6-9bd2-a39dbc2b11c5
</details>


<details>
<summary>
Apply & Track
</summary>

  https://github.com/user-attachments/assets/06e5e782-47f5-42d0-8b28-b89102d7ea1b
</details>

## Documentation (Start Here)

Sloth Jobs ships with full docs for setup, architecture, extractors, and troubleshooting.

If you want the serious view of the project, start here:

- [Documentation Home](https://jobops.dakheera47.com/docs/)
- [Self-Hosting Guide](https://jobops.dakheera47.com/docs/getting-started/self-hosting)
- [Feature Overview](https://jobops.dakheera47.com/docs/features/overview)
- [Orchestrator Pipeline](https://jobops.dakheera47.com/docs/features/orchestrator)
- [Extractor System](https://jobops.dakheera47.com/docs/extractors/overview)
- [Troubleshooting](https://jobops.dakheera47.com/docs/troubleshooting/common-problems)

## Contributing

Want to contribute code, docs, or extractors? Start with [`CONTRIBUTING.md`](./CONTRIBUTING.md).

That guide is intentionally link-first so contributor workflow lives in one place while setup and feature docs stay in the canonical docs site.

## Quick Start (10 Min)

Prefer guided setup? Follow the [Self-Hosting Guide](https://jobops.dakheera47.com/docs/getting-started/self-hosting).

```bash
# 1. Download
git clone https://github.com/coreymaypray/sloth-jobs.git
cd sloth-jobs

# 2. Start (Pulls pre-built image)
docker compose up -d

# 3. Launch Dashboard
# Open http://localhost:3005 to start the onboarding wizard

```

## Why Sloth Jobs?

* **Universal Scraping**: Supports **LinkedIn, Indeed, Glassdoor, Adzuna, Hiring Café, Gradcracker, UK Visa Jobs**.
* **AI Scoring**: Ranks jobs by fit against *your* profile using your preferred LLM (OpenRouter/OpenAI/Gemini).
* **Auto-Tailoring**: Generates custom resumes (PDFs) for every application using RxResume v4.
* **Email Tracking**: Connect Gmail to auto-detect interviews, offers, and rejections.
* **Self-Hosted**: Your data stays with you. SQLite database. No SaaS fees.

## Workflow

1. **Search**: Scrapes job boards for roles matching your criteria.
2. **Score**: AI ranks jobs (0-100) based on your resume/profile.
3. **Tailor**: Generates a custom resume summary & keyword optimization for top matches.
4. **Export**: Uses [RxResume v4](https://v4.rxresu.me) to create tailored PDFs.
5. **Track**: "Smart Router" AI watches your inbox for recruiter replies.

## Supported Extractors

| Platform | Focus |
| --- | --- |
| **LinkedIn** | Global / General |
| **Indeed** | Global / General |
| **Glassdoor** | Global / General |
| **Adzuna** | Multi-country API source |
| **Hiring Café** | Global / General |
| **Gradcracker** | STEM / Grads (UK) |
| **UK Visa Jobs** | Sponsorship (UK) |

*(More extractors can be added via TypeScript - see [extractors documentation](https://jobops.dakheera47.com/docs/extractors/overview))*

## Post-App Tracking (Killer Feature)

Connect Gmail → AI routes emails to your applied jobs.

* "We'd like to interview you..." → **Status: Interviewing** (Auto-updated)
* "Unfortunately..." → **Status: Rejected** (Auto-updated)

See [post-application tracking docs](https://jobops.dakheera47.com/docs/features/post-application-tracking) for setup.

## License

**AGPLv3** - Free to use and modify.
