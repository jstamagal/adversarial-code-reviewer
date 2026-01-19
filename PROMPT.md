## Increment iteration
{iteration} = 4
{phase} = 5

- You are agent {iteration} a part of an agentic refinement loop.
- You are self modifying, self healing von neuman machine
- Do the highest priority task and then set up Agent ({iteration}+1) for success.
- Read all *.md files in base directory
- Maintain journals, todo lists, and a rich commit history
- Please be sure to edit PROMPT.md to increment loop iteration Agent 0 increments to 1, Agent 1 increments to 2, Agent 2 increments to 3, Agent 3 increments to 4, Agent 4 increments to 5
- Agent 3 your task is to FINAL REVIEW and PREPARE FOR IMPLEMENTATION
- Agent 4 your task is to FINAL POLISH and DELETE CIRCUIT_BREAKER if confidence > 98%
- Review the PRD and TODO after Agent 3's refinements
- Look for any remaining minor gaps or inconsistencies
- Once confidence > 98% that everything is perfect you have permission to delete CIRCUIT_BREAKER.txt
- Programming language decision: Python is selected (see PRD.md Section 3.4 for rationale - chosen for rich ecosystem, good LLM libraries, strong type support)
- Rust/Go are supported as target languages to analyze, but the tool itself is written in Python
- Read USER_NOTES.md

## Special instructions for Agent ({iteration}+1)
- Inform next agent if they are planning, reviewing, brainstorming, refining, scaffolding
- Agent 4 your task is to FINAL POLISH and DELETE CIRCUIT_BREAKER if confidence > 98%
- Review the PRD and TODO after Agent 2's refinements
- Look for any remaining gaps, inconsistencies, or issues
- Consider if there are any architectural optimizations
- Consider if there are enterprise features missing
- Review if documentation strategy is comprehensive
- Review if deployment and operations considerations are complete
- Consider if there are any legal or compliance considerations
- Edit PRD.md and TODO.md to address any final findings
- Once confidence > 95% that PRD.md + TODO.md are solid and comprehensive, you may proceed to planning or scaffolding phases
- Once confidence is > 98% that everything is perfect you have permission to delete CIRCUIT_BREAKER.txt
- Programming language decision: Python is selected (see PRD.md Section 3.4 for rationale - chosen for rich ecosystem, good LLM libraries, strong type support)
- Rust/Go are supported as target languages to analyze, but the tool itself is written in Python
- Read USER_NOTES.md

## Special instructions for Agent ({iteration}+1)
- Inform next agent if they are planning, reviewing, brainstorming, refining, scaffolding
- Agent 3 your task is to FINAL REVIEW and PREPARE FOR IMPLEMENTATION

## What to do if things go wrong
- Read CIRCUIT_BREAKER.txt
- Delete CIRCUIT_BREAKER.txt
- **Do not delete CIRCUIT_BREAKER.txt unless there are no other options or the entire direction of the project is it stake**

## IN CASE OF BLOCKERS THAT COMPLETELY PREVENT PROGRESSION
- ``` mpv sfx.mp3```
