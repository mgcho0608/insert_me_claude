"""
LLM adapter registry for insert_me.

Adapters are resolved by name from config. The default is always "noop".
All adapters implement the LLMAdapter interface from insert_me.llm.adapter.

Registered adapters
-------------------
noop        NoOpAdapter — returns stubs, no network calls, always available.

To register additional adapters (e.g. for a real LLM endpoint), import them
here and add to ADAPTER_REGISTRY.
"""

from insert_me.llm.adapter import LLMAdapter, NoOpAdapter

ADAPTER_REGISTRY: dict[str, type[LLMAdapter]] = {
    "noop": NoOpAdapter,
    # TODO(phase7): register real adapters here, e.g.:
    # "openai_compat": OpenAICompatAdapter,
}


def get_adapter(name: str = "noop", **kwargs) -> LLMAdapter:
    """
    Resolve and instantiate an LLM adapter by name.

    Parameters
    ----------
    name:
        Adapter name, as specified in [llm].adapter config key.
    **kwargs:
        Passed to the adapter constructor (e.g. endpoint, model, timeout).

    Returns
    -------
    LLMAdapter
        Ready-to-use adapter instance.

    Raises
    ------
    ValueError
        If no adapter with the given name is registered.
    """
    cls = ADAPTER_REGISTRY.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown LLM adapter '{name}'. "
            f"Registered adapters: {list(ADAPTER_REGISTRY)}"
        )
    return cls(**kwargs)
