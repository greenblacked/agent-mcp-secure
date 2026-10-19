# Controls

This document describes the practical controls promoted by this repository and why they exist.

## 1. Least-privilege tools

**What**: Design or wrap tools so each tool can do only what is required for a specific task. Avoid general-purpose shell, unrestricted file system, or broad cloud admin tools when a narrower interface is possible.

**Why**: Reduces the impact of a successful prompt injection. Even if the model is steered, the available actions are limited.

**Example pattern**: See `patterns/least-privilege/`.

## 2. Human approval for high-impact actions

**What**: Require explicit human confirmation before executing actions that can modify data, spend money, change infrastructure, or access secrets.

**Why**: Breaks the automated chain from injected instruction to harmful action. The model can request the action, but a human decides.

**Example pattern**: See `patterns/human-approval/`.

## 3. Argument validation and output sanitization

**What**: Validate tool arguments against strict schemas (paths under allowed roots, no shell metacharacters, allowed hosts, etc.). Sanitize or mark external content before it is returned to the model.

**Why**: Prevents classic injection (command, path, SSRF) even when the model supplies malicious arguments. Reduces the chance that tool output itself becomes an injection vector.

**Example pattern**: See `patterns/output-sanitization/`.

## 4. Static checks on tool definitions

**What**: Scan MCP tool descriptions and schemas for steering language, references to sensitive paths, overly broad capabilities, and obfuscation before trusting the server.

**Why**: Tool descriptions are attacker-controlled when the MCP server is untrusted or compromised. Detecting steering instructions early reduces risk.

**Location**: `checks/`.

## 5. Detection of anomalous tool use

**What**: Log tool calls and look for sequences that indicate abuse (reading credentials after processing untrusted content, unusual tool combinations, data leaving the expected boundary).

**Why**: Provides detection when preventive controls are bypassed or incomplete.

**Location**: `detections/`.
