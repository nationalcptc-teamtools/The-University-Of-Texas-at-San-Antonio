# Repository destination and publication

- This checkout's development destination is the private repository
  `Moriz82/cptc-private-toolkit`. Keep it private.
- Push only with explicit user authorization, and only to the private
  repository. The user authorized the initial private push on 2026-09-07.
- Apply Git identity, authentication, branch, and remote settings with
  repository-local configuration. Do not change global Git configuration
  or other repositories for this project's setup.
- Never push this work to the public
  `nationalcptc-teamtools/The-University-Of-Texas-at-San-Antonio` repository.
  The `public-upstream` remote is for fetching only; its push URL is disabled.
- Preserve the existing local history and tooling. Do not publish reports,
  engagement evidence, credentials, or other data as part of repository setup.
- For the approved guarded CPTC harness build, use `gpt-5.6-luna` for the
  named planner, implementer and independent reviewer; use `gpt-5.6-terra`
  workers for enforcement, audit and transport. This project-only exception
  was explicitly approved on 2026-09-07. Do not change global model settings.
- At most two write agents may run concurrently, with disjoint file ownership.
  Main owns shared interfaces, migrations, integration and release acceptance.
- Build agents use source and synthetic fixtures only, never credentials or
  raw engagement data. No automatic provider fallback or model substitution.
