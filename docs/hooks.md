# Hooks

Hooks run your own programs before and after a run. They can also send the run report to a webhook.

```yaml
hooks:
  timeout: 30s                       # default for every hook
  before:
    - run: [/etc/ipsetfw/hooks/sync-mirror.sh, internal.example.com]
      onFailure: abort               # abort (default): stop, change nothing | warn: go on
  after:
    - run: [/etc/ipsetfw/hooks/health-check.sh, http://127.0.0.1/health]
      when: changed                  # always (default) | changed
      onFailure: rollback            # warn (default) | rollback
  onError:
    - webhook: https://alerts.example.com/ipsetfw
```

## Program hooks

- A hook is a program and its arguments. It is never a shell string. `run[0]` must be an absolute path.
- Hooks run as root, so each program is checked first. The file must be owned by root, not writable by group or others, and executable. Otherwise the hook is refused and counts as failed. `-plan` shows this too.
- A hook gets a fixed `PATH`, and only these variables: `IPSETFW_EVENT`, `IPSETFW_ACTION` (`apply` or `clear`), `IPSETFW_CONFIG`, `IPSETFW_RESULT`, `IPSETFW_CHANGED`, `IPSETFW_ERROR`, `IPSETFW_FAILED`, and `IPSETFW_REPORT`.
- `IPSETFW_REPORT` is the path to the run report as JSON. It is a private temporary file, removed after the hook runs. Read it with `jq`.
- A timeout kills the hook and everything it started.
- Output is shown with a `[hook after 1]` prefix, and written to the log file.

## When they run

- The order is: before hooks, then the run, then after hooks, then onError hooks if the run failed.
- A before hook that fails with `abort` stops the run before anything is changed.
- After hooks run only when the run succeeded.
- `when: changed` runs an after hook only when some list really changed.
- Hooks run for apply and `-clear`. They never run for `-plan`, `-status`, `-verify` or `-restore`.
- A failing after hook makes the run exit 1. The change is kept, unless the hook rolled back.

## Rollback

`onFailure: rollback` on an after hook puts every list this run updated back to its previous contents.

- The firewall rules and allow-only are not rolled back. The run says so.
- A list on its first update has no previous contents, so it can't be rolled back. The run says so too.
- Use it with a health check. The example `contrib/hooks/health-check.sh` does this.

## Webhooks

`webhook: https://...` on any hook sends the run report as JSON.

- The request is `POST` with `Content-Type: application/json` and `User-Agent: ipsetfw`.
- A 2xx answer is success.
- `retries: N` retries after a failure, waiting 1s, 2s, 4s and so on, at most 30s.
- `timeout` limits each attempt.
- Messages and logs show only `webhook https://host`, never the path or query. Webhook URLs often hold a token.
- `when: changed` works for webhooks too.

## onError

`onError` hooks run when a run failed, after a rollback, or when a before hook aborted the run.

- They get `IPSETFW_RESULT=failed`, and the errors, including each failed list's reason.
- A failing onError hook only prints a warning. It never changes the exit code.

## Testing

- `ipsetfw -config x.yml -test-hook after` runs one event's hooks against a sample report. It changes nothing.
- `-plan` lists the hooks, and flags any program that would be refused.
- `-test-hook` with a webhook sends the sample report to the real URL.

## Examples

`contrib/hooks/` has two scripts:

- `health-check.sh`: checks a URL, and fails if it stops answering. Use it with `onFailure: rollback`.
- `save-to-file.sh`: keeps a copy of every run's report.
