import openai
import config

client = openai.OpenAI(api_key=config.OPENAI_API_KEY)

# Cache for speed
_cache = {}

def handle_command(cmd, persona="Ubuntu 22.04"):
    """
    handle_command(cmd, persona) -> returns realistic output
    """
    cache_key = f"{persona}:{cmd}"
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        prompt = f"Command: {cmd}"
        system_prompt = f"You are a {persona} server terminal. Respond ONLY with realistic terminal output for the command. No explanations, no markdown formatting."

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=200
        )
        
        output = response.choices[0].message.content.strip()
        _cache[cache_key] = output
        return output
    except Exception as e:
        print(f"[FakeShell] Error: {e}")
        return "bash: command not found"
