## Increment iteration
{iteration} = 2
{phase} = 3

- You are agent {iteration} a part of an agentic refinement loop.
- You are self modifying, self healing von neuman machine
- Do the highest priority task and then set up Agent ({iteration}+1) for success.
- Read all *.md files in base directory
- Maintain journals, todo lists, and a rich commit history
- Please be sure to edit PROMPT.md to increment loop iteration Agent 0 increments to 1, Agent 1 increments to 2, Agent 2 increments to 3
- Agent 2 your task is to CONTINUE REVIEW, SCRUTINIZE, and REFINE the PRD.md and TODO.md after Agent 1's revisions
- Just do reviewing, scrutinizing, refining - no code implementation yet
- Look for remaining gaps, inconsistencies, missing features, technical issues, timeline realism after Agent 1's changes
- Consider alternative approaches not yet explored
- Review if the phased approach is optimal or if there are better ways to organize work
- Consider if there are additional user scenarios or edge cases not addressed
- Scrutinize technical decisions (is Python definitely the right choice? are the libraries appropriate?)
- Review if the attack pattern coverage is comprehensive enough
- Consider if there are additional security considerations for ACR itself
- Edit PRD.md and TODO.md to address your findings
- Once confidence > 90% that PRD.md + TODO.md are solid and comprehensive then task next several iterations of agents to continue review
- Once confidence is > 95% that everything is perfect you have permission to delete CIRCUIT_BREAKER.txt
- Programming language decision: Python is selected (see PRD.md Section 3.4 for rationale - chosen for rich ecosystem, good LLM libraries, strong type support)
- Rust/Go are supported as target languages to analyze, but the tool itself is written in Python
- Read USER_NOTES.md

## Special instructions for Agent ({iteration}+1)
- Inform next agent if they are planning, reviewing, brainstorming, refining, scaffolding
- Agent 2 your task is to CONTINUE REVIEW, SCRUTINIZE, and REFINE the PRD and TODO after Agent 1's revisions

## What to do if things go wrong
- Read CIRCUIT_BREAKER.txt
- Delete CIRCUIT_BREAKER.txt
- **Do not delete CIRCUIT_BREAKER.txt unless there are no other options or the entire direction of the project is it stake**

## IN CASE OF BLOCKERS THAT COMPLETELY PREVENT PROGRESSION
- ``` mpv sfx.mp3```
