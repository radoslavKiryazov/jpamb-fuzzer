# 🚀 Quick GitHub Guide

This section outlines the essential Git commands for working together efficiently on this project.

## 🔄 Typical Workflow

Pull the latest version

git pull


Create a new branch for your work

git checkout -b feature/<short-description>


Example:

git checkout -b feature/symbolic-execution


Make your changes
Edit code, add tests, update docs, etc.

Stage and commit

git add .
git commit -m "Implement symbolic execution core"


Push your branch

git push -u origin feature/symbolic-execution


Create a Pull Request (PR)

Go to the repository on GitHub.

Click Compare & pull request.

Add a short description and request review.

🧩 Common Commands
| **Command**               | **What it does**                  |
| ------------------------- | --------------------------------- |
| `git status`              | Check what has changed            |
| `git add <file>`          | Stage a specific file             |
| `git commit -m "message"` | Save your changes                 |
| `git pull`                | Sync with the latest version      |
| `git push`                | Upload your commits               |
| `git checkout main`       | Switch back to main branch        |
| `git merge <branch>`      | Merge another branch into current |
| `git branch -d <branch>`  | Delete a local branch             |

🤝 Collaboration Tips

Always pull before starting new work.

Use branches for every feature or fix.

Write clear commit messages.

Review and comment on PRs before merging.

Delete old branches after merging to keep things tidy.
