# cveraptor full-width + restored date sort patch

This patch combines the expanded “Check if this affects your system” page with the dashboard date sorting and full-width layout.

Changed files:
- `frontend/src/App.jsx`
- `frontend/src/App.css`
- `frontend/src/index.css`
- `backend/app/main.py`
- `backend/app/services/nvd_service.py`
- `backend/app/services/ssvc_decision_service.py`
- `backend/app/config/ssvc_decision_rules.json`

What changed:
- Restores the dashboard sort controls:
  - `Published` / `Last modified`
  - `Newest first` / `Oldest first`
- Keeps the sort state when searching, refreshing, filtering, changing page size, and paginating.
- Keeps the expanded CVE intelligence view on the “Check if this affects your system” page.
- Removes the narrow fixed root width and makes the page follow the browser/screen width.

Apply from your project root:

```bash
cd ~/documents/cveraptor
unzip ~/Downloads/cveraptor_fullwidth_sort_restore_patch.zip -d .
docker compose up --build
```

Then hard refresh the browser:

```text
Ctrl + Shift + R
```
