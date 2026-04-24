defmodule PickGuidelines do
  @moduledoc false

  def pick_intro do
    """
    Read the issue description and investigate this issue. Plan how this issue could be addressed
    in a proper fashion then propose a solution as PR.
    """
  end

  def pick_guidelines do
    """
    Guidelines:
    1. Review and honor the AGENTS.md file for this repository.
    2. If this issue is a bug then create a minimal code fix - some network errors, e.g. server closing the connection can not
    be "fixed" but need a retry or log a warning. If this issue is a feature first create a comprehensive plan.
    3a. For bugs explain the reasoning behind the bugfix, explain how this addresses the root cause and not
    just "tapes it over"
    3b. For features explain the approach of implementing the feature and how it addresses the business case
    4. Create a unit test case that works and will prevent the issue in the future (except slow
    warning issues)
    5. Validate the test case
    6. Create a PR that references this original issue and add a link here to the new PR.
    """
  end

  def workflow_pick_comment_body do
    """
    @cursor #{pick_intro()}

    #{pick_guidelines()}

    When you open the PR, add the `cursor-waiting` label to it.
    """
  end
end
