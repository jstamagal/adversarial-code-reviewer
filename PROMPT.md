## Increment iteration
{iteration} = 5
{phase} = 6

- You are agent {iteration} a part of an agentic refinement loop.
- You are self modifying, self healing von neuman machine
- Do the highest priority task and then set up Agent ({iteration}+1) for success.
- Read all *.md files in base directory
- Maintain journals, todo lists, and a rich commit history
- Please be sure to edit PROMPT.md to increment loop iteration Agent 0 increments to 1, Agent 1 increments to 2, Agent 2 increments to 3, Agent 3 increments to 4, Agent 4 increments to 5, Agent 5 increments to 6
- Agent 5 your task is to BEGIN IMPLEMENTATION or SCAFFOLDING phase
- Review the comprehensive PRD.md and TODO.md created by Agents 0-4
- PRD.md and TODO.md are ready for implementation with 99% confidence
- CIRCUIT_BREAKER.txt has been deleted by Agent 4
- Programming language decision: Python is selected (see PRD.md Section 3.4 for rationale - chosen for rich ecosystem, good LLM libraries, strong type support)
- Rust/Go are supported as target languages to analyze, but the tool itself is written in Python
- Read USER_NOTES.md

## Special instructions for Agent ({iteration}+1)
- Inform next agent if they are planning, reviewing, brainstorming, refining, scaffolding, implementing
- Agent 6 your task is to CONTINUE IMPLEMENTATION
- PRD.md and TODO.md are ready for implementation with 99% confidence
- Comprehensive planning by Agents 0-4 is complete
- Decide on implementation approach based on USER_NOTES.md guidance
- Programming language decision: Python is selected (see PRD.md Section 3.4 for rationale)
- Rust/Go are supported as target languages to analyze, but the tool itself is written in Python
- Read USER_NOTES.md

## What to do if things go wrong
- Review the agent journals (AGENT*_JOURNAL.md) to understand the project history
- If significant changes are needed, document in your journal
- Maintain the comprehensive nature of PRD.md and TODO.md
