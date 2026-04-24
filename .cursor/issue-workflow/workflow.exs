#!/usr/bin/env elixir
# Advances GitHub workflow labels per .cursor/issue-workflow/README.md (cron / every ~5 min).

Mix.install([:jason])

dir = Path.dirname(Path.expand(__ENV__.file))
Code.require_file(Path.join(dir, "pick_guidelines.exs"))

defmodule IssueWorkflow do
  @moduledoc false

  @list_limit 500
  @wait_seconds 3600
  @gh_retry_max_attempts 5

  @ci_fix_marker ~r/<!--\s*cursor-workflow:ci-fix\s+head=([a-f0-9]{40})\s*-->/
  @demo_marker ~r/<!--\s*cursor-workflow:demo\s+head=([a-f0-9]{40})\s*-->/

  def run do
    log("workflow start")
    slug = repo_slug()
    log("repository #{slug}")
    [owner, repo] = String.split(slug, "/", parts: 2)

    picks_raw =
      gh_json!(["issue", "list", "--state", "open", "--label", "cursor-pick", "-L", "#{@list_limit}", "--json", "number,labels"])
      |> Jason.decode!()

    waits_raw =
      gh_json!(["pr", "list", "--state", "open", "--label", "cursor-waiting", "-L", "#{@list_limit}", "--json", "number,labels"])
      |> Jason.decode!()

    ci_raw =
      gh_json!(["pr", "list", "--state", "open", "--label", "cursor-waiting-for-ci", "-L", "#{@list_limit}", "--json", "number,labels"])
      |> Jason.decode!()

    demo_raw =
      gh_json!(["pr", "list", "--state", "open", "--label", "cursor-demo", "-L", "#{@list_limit}", "--json", "number,labels"])
      |> Jason.decode!()

    picks = reject_if_ignore(picks_raw)
    waits = reject_if_ignore(waits_raw)
    ci = reject_if_ignore(ci_raw)
    demo = reject_if_ignore(demo_raw)

    log(
      "issues label=cursor-pick: #{length(picks_raw)} matched, #{length(picks_raw) - length(picks)} skipped (cursor-ignore), #{length(picks)} to process #{inspect(Enum.map(picks, & &1["number"]))}"
    )

    log(
      "PRs label=cursor-waiting: #{length(waits_raw)} matched, #{length(waits_raw) - length(waits)} skipped (cursor-ignore), #{length(waits)} to process #{inspect(Enum.map(waits, & &1["number"]))}"
    )

    log(
      "PRs label=cursor-waiting-for-ci: #{length(ci_raw)} matched, #{length(ci_raw) - length(ci)} skipped (cursor-ignore), #{length(ci)} to process #{inspect(Enum.map(ci, & &1["number"]))}"
    )

    log(
      "PRs label=cursor-demo: #{length(demo_raw)} matched, #{length(demo_raw) - length(demo)} skipped (cursor-ignore), #{length(demo)} to process #{inspect(Enum.map(demo, & &1["number"]))}"
    )

    Enum.each(picks, &advance_pick(&1["number"]))
    Enum.each(waits, &advance_waiting(owner, repo, &1["number"]))
    Enum.each(ci, &advance_waiting_for_ci(owner, repo, &1["number"]))
    Enum.each(demo, &advance_demo(owner, repo, &1["number"]))
    log("workflow finished")
  end

  defp log(message) do
    ts =
      DateTime.utc_now()
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

    IO.puts("[#{ts}] #{message}")
  end

  defp repo_slug do
    case System.get_env("GITHUB_REPOSITORY") do
      nil ->
        gh_json!(["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"]) |> String.trim()

      slug ->
        slug
    end
  end

  defp reject_if_ignore(items) do
    Enum.reject(items, fn item ->
      Enum.any?(item["labels"] || [], &(&1["name"] == "cursor-ignore"))
    end)
  end

  defp advance_pick(n) do
    num = to_string(n)
    log("cursor-pick ##{num}: action remove-label cursor-pick")
    gh!(["issue", "edit", num, "--remove-label", "cursor-pick"])

    log("cursor-pick ##{num}: action issue comment (@cursor + guidelines)")
    gh!(["issue", "comment", num, "--body", PickGuidelines.workflow_pick_comment_body()])

    log("cursor-pick ##{num}: action add-label cursor-pr-open")
    gh!(["issue", "edit", num, "--add-label", "cursor-pr-open"])
    log("cursor-pick ##{num}: transition complete")
  end

  defp advance_waiting(owner, repo, n) do
    num = to_string(n)

    case last_issue_comment_at(owner, repo, n) do
      nil ->
        log("cursor-waiting ##{num}: no timeline comments yet — posting @gemini review this PR")
        gh!(["pr", "comment", num, "--body", "@gemini review this PR"])

      ts ->
        age = DateTime.diff(DateTime.utc_now(), ts, :second)

        cond do
          age < @wait_seconds ->
            log(
              "cursor-waiting ##{num}: skip — last timeline comment #{age}s ago (need ≥#{@wait_seconds}s); last_comment_at=#{DateTime.to_iso8601(ts)}"
            )

          true ->
            log(
              "cursor-waiting ##{num}: gate passed (#{age}s since last timeline comment); advancing (last_comment_at=#{DateTime.to_iso8601(ts)})"
            )

            log("cursor-waiting ##{num}: action remove-label cursor-waiting")
            gh!(["pr", "edit", num, "--remove-label", "cursor-waiting"])

            log("cursor-waiting ##{num}: action pr comment (@cursor /branch-code-review)")
            gh!(["pr", "comment", num, "--body", "@cursor /branch-code-review and fix the issues found"])

            log("cursor-waiting ##{num}: action add-label cursor-waiting-for-ci")
            gh!(["pr", "edit", num, "--add-label", "cursor-waiting-for-ci"])
            log("cursor-waiting ##{num}: transition complete → cursor-waiting-for-ci")
        end
    end
  end

  defp advance_waiting_for_ci(owner, repo, n) do
    num = to_string(n)
    head_oid = pr_head_oid(num)

    checks =
      gh_json!(["pr", "checks", num, "--json", "name,state,bucket,link,workflow"])
      |> Jason.decode!()

    cond do
      checks == [] ->
        log("cursor-waiting-for-ci ##{num}: skip — no checks reported by gh")

      Enum.any?(checks, &(&1["bucket"] == "pending")) ->
        names =
          checks
          |> Enum.filter(&(&1["bucket"] == "pending"))
          |> Enum.map(& &1["name"])
          |> Enum.join(", ")

        log("cursor-waiting-for-ci ##{num}: skip — CI still pending (#{names})")

      true ->
        failed = Enum.filter(checks, &(&1["bucket"] == "fail"))
        cancelled = Enum.filter(checks, &(&1["bucket"] == "cancel"))

        cond do
          failed != [] ->
            advance_ci_failed(owner, repo, num, head_oid, failed)

          cancelled != [] ->
            advance_ci_cancelled(owner, repo, num, head_oid, cancelled)

          Enum.all?(checks, &(&1["bucket"] in ["pass", "skipping"])) ->
            log(
              "cursor-waiting-for-ci ##{num}: all checks green/skipped — moving to cursor-demo"
            )

            log("cursor-waiting-for-ci ##{num}: action remove-label cursor-waiting-for-ci")
            gh!(["pr", "edit", num, "--remove-label", "cursor-waiting-for-ci"])

            log("cursor-waiting-for-ci ##{num}: action add-label cursor-demo")
            gh!(["pr", "edit", num, "--add-label", "cursor-demo"])
            log("cursor-waiting-for-ci ##{num}: transition complete → cursor-demo")

          true ->
            bad =
              checks
              |> Enum.reject(&(&1["bucket"] in ["pass", "fail", "pending", "skipping", "cancel"]))
              |> Enum.map_join(", ", & &1["bucket"])

            log(
              "cursor-waiting-for-ci ##{num}: skip — unexpected check buckets (#{bad}); needs manual review"
            )
        end
    end
  end

  defp advance_demo(owner, repo, n) do
    num = to_string(n)
    head_oid = pr_head_oid(num)
    comments = fetch_all_issue_comments(owner, repo, num)
    prompted_for = latest_demo_head_oid(comments)

    cond do
      prompted_for == head_oid ->
        log(
          "cursor-demo ##{num}: demo prompt already posted for head #{String.slice(head_oid, 0, 7)}… — skip duplicate comment"
        )

      true ->
        log(
          "cursor-demo ##{num}: posting @cursor demo (CLI) prompt (head #{String.slice(head_oid, 0, 7)}…)"
        )

        gh!(["pr", "comment", num, "--body", demo_comment(head_oid)])
    end

    log("cursor-demo ##{num}: action remove-label cursor-demo")
    gh!(["pr", "edit", num, "--remove-label", "cursor-demo"])

    log("cursor-demo ##{num}: action add-label cursor-waiting-for-human")
    gh!(["pr", "edit", num, "--add-label", "cursor-waiting-for-human"])
    log("cursor-demo ##{num}: transition complete → cursor-waiting-for-human")
  end

  defp advance_ci_failed(owner, repo, num, head_oid, failed) do
    comments = fetch_all_issue_comments(owner, repo, num)
    prompted_for = latest_ci_fix_head_oid(comments)

    cond do
      prompted_for == head_oid ->
        log(
          "cursor-waiting-for-ci ##{num}: CI still failing on same head #{String.slice(head_oid, 0, 7)}… — skip duplicate @cursor CI prompt"
        )

      true ->
        log(
          "cursor-waiting-for-ci ##{num}: CI failed — posting @cursor prompt (head #{String.slice(head_oid, 0, 7)}…, last prompt was #{format_optional_oid(prompted_for)})"
        )

        gh!(["pr", "comment", num, "--body", ci_fix_comment(head_oid, failed)])
    end
  end

  defp advance_ci_cancelled(owner, repo, num, head_oid, cancelled) do
    comments = fetch_all_issue_comments(owner, repo, num)
    prompted_for = latest_ci_fix_head_oid(comments)

    cond do
      prompted_for == head_oid ->
        log(
          "cursor-waiting-for-ci ##{num}: CI still shows cancelled runs on same head #{String.slice(head_oid, 0, 7)}… — skip duplicate @cursor cancelled-CI prompt"
        )

      true ->
        log(
          "cursor-waiting-for-ci ##{num}: CI cancelled — posting @cursor prompt (head #{String.slice(head_oid, 0, 7)}…, last prompt was #{format_optional_oid(prompted_for)})"
        )

        gh!(["pr", "comment", num, "--body", ci_cancel_comment(head_oid, cancelled)])
    end
  end

  defp format_optional_oid(nil), do: "none"

  defp format_optional_oid(oid), do: String.slice(oid, 0, 7) <> "…"

  defp ci_fix_comment(head_oid, failed) do
    lines =
      Enum.map(failed, fn c ->
        "- **#{c["name"]}** — `#{c["state"]}` — #{c["link"]}"
      end)

    """
    @cursor GitHub Actions failed on commit `#{head_oid}` (current PR head). Fix the failing jobs, push, and let CI re-run. This PR stays labeled `cursor-waiting-for-ci` until CI is green.

    Failed checks:
    #{Enum.join(lines, "\n")}

    <!-- cursor-workflow:ci-fix head=#{head_oid} -->
    """
  end

  defp ci_cancel_comment(head_oid, cancelled) do
    lines =
      Enum.map(cancelled, fn c ->
        "- **#{c["name"]}** — `#{c["state"]}` — #{c["link"]}"
      end)

    """
    @cursor **Cancelled CI runs** on commit `#{head_oid}` (current PR head). This PR stays labeled `cursor-waiting-for-ci` until CI is green.

    **Cancelled checks (review these runs first):**
    #{Enum.join(lines, "\n")}

    If a run was cancelled or stopped because of a failure or timeout caused by this PR, follow the logs for the run(s) above, fix the issue, and push. If you believe this was a flake, an accidental cancellation, or infra noise, re-run the workflow from the Actions UI (or restart the job) instead of changing code.

    <!-- cursor-workflow:ci-fix head=#{head_oid} -->
    """
  end

  defp demo_comment(head_oid) do
    """
    @cursor Update the **PR description** with CLI-focused demo material for this change, unless it already matches the current head and is enough for a reviewer to verify the behavior.

    Include a short **how to try it**: relevant `diode` subcommands and flags (or other binaries this PR touches), any minimal setup, and **representative terminal output** as fenced code blocks—focused on what this PR changes, not a generic walkthrough.

    Keep this in the **GitHub PR description** only; do not add demo-only files, logs, or images to the branch unless the issue or review explicitly asked for them.

    <!-- cursor-workflow:demo head=#{head_oid} -->
    """
  end

  defp latest_demo_head_oid(comments) do
    comments
    |> Enum.reject(&(is_nil(&1["created_at"])))
    |> Enum.sort(fn a, b ->
      DateTime.compare(parse_github_iso8601(a["created_at"]), parse_github_iso8601(b["created_at"])) == :gt
    end)
    |> Enum.find_value(fn c ->
      case Regex.run(@demo_marker, c["body"] || "") do
        [_, oid] -> oid
        _ -> nil
      end
    end)
  end

  defp latest_ci_fix_head_oid(comments) do
    comments
    |> Enum.reject(&(is_nil(&1["created_at"])))
    |> Enum.sort(fn a, b ->
      DateTime.compare(parse_github_iso8601(a["created_at"]), parse_github_iso8601(b["created_at"])) == :gt
    end)
    |> Enum.find_value(fn c ->
      case Regex.run(@ci_fix_marker, c["body"] || "") do
        [_, oid] -> oid
        _ -> nil
      end
    end)
  end

  defp pr_head_oid(num) do
    json = gh_json!(["pr", "view", num, "--json", "headRefOid"])
    Jason.decode!(json)["headRefOid"]
  end

  defp last_issue_comment_at(owner, repo, issue_num) do
    fetch_all_issue_comments(owner, repo, issue_num)
    |> Enum.map(& &1["created_at"])
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&parse_github_iso8601/1)
    |> max_datetime()
  end

  defp max_datetime([]), do: nil

  defp max_datetime([h | t]),
    do: Enum.reduce(t, h, fn d, acc -> if DateTime.compare(d, acc) == :gt, do: d, else: acc end)

  defp fetch_all_issue_comments(owner, repo, issue_num, page \\ 1, acc \\ []) do
    path = "repos/#{owner}/#{repo}/issues/#{issue_num}/comments?per_page=100&page=#{page}"
    batch = gh_json!(["api", path]) |> Jason.decode!()

    cond do
      batch == [] ->
        acc

      length(batch) < 100 ->
        acc ++ batch

      true ->
        fetch_all_issue_comments(owner, repo, issue_num, page + 1, acc ++ batch)
    end
  end

  defp parse_github_iso8601(str) do
    {:ok, dt, _} = DateTime.from_iso8601(str)
    dt
  end

  defp gh_json!(args), do: gh!(args)

  # GitHub CLI surfaces API outages as e.g. "non-200 OK status code: 504 Gateway Timeout".
  defp retryable_github_server_error?(output), do: output =~ ~r/status code: 5\d\d\b/

  defp gh!(args), do: gh!(args, @gh_retry_max_attempts)

  defp gh!(args, attempts_left) do
    case System.cmd("gh", args, stderr_to_stdout: true) do
      {out, 0} ->
        out

      {out, code} ->
        cond do
          attempts_left > 1 && retryable_github_server_error?(out) ->
            nth = @gh_retry_max_attempts - attempts_left
            delay_ms = min(16_000, 2_000 * Integer.pow(2, nth))

            log(
              "gh HTTP 5xx (exit #{code}), retrying in #{delay_ms}ms (#{attempts_left - 1} attempt(s) left): #{Enum.join(args, " ")}"
            )

            Process.sleep(delay_ms)
            gh!(args, attempts_left - 1)

          true ->
            ts =
              DateTime.utc_now()
              |> DateTime.truncate(:second)
              |> DateTime.to_iso8601()

            IO.puts(:stderr, "[#{ts}] gh failed (#{code}): #{inspect(Enum.join(args, " "))}")
            IO.puts(:stderr, out)
            System.halt(1)
        end
    end
  end
end

IssueWorkflow.run()
