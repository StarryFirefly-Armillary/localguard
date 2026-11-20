# ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, require, or install dependencies.
# No Rails app is booted, and no action is called.
class FixtureController < ApplicationController
  def vulnerable_command
    supplied = params[:fixture_command]
    command = "fixture-tool #{supplied}"
    # ruleid: localguard.security.ruby-rails-shell
    system(command)
  end

  def clean_command
    supplied = params[:fixture_argument]
    # ok: localguard.security.ruby-rails-shell
    system("fixture-tool", supplied)
    # ok: localguard.security.ruby-rails-shell
    system("fixture-tool --version")
  end

  def vulnerable_deserialization
    supplied = params[:fixture_data]
    forwarded = supplied
    # ruleid: localguard.security.ruby-rails-marshal
    Marshal.load(forwarded)
  end

  def clean_deserialization
    supplied = params[:fixture_data]
    # ok: localguard.security.ruby-rails-marshal
    JSON.parse(supplied)
  end

  def clean_trusted_deserialization(trusted_local_bytes)
    # ok: localguard.security.ruby-rails-marshal
    Marshal.load(trusted_local_bytes)
  end
end
