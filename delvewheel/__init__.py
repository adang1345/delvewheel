class _Config:
    """Global configuration options for this delvewheel invocation"""
    # verbosity level, 0 to 2
    verbose: int = 0

    # testing options for internal use
    # not_enough_padding: assume that each PE file contains insufficient
    #   internal padding to write mangled names
    # header_space: assume that each PE file has insufficient space in the
    #   section table to add a new section header
    test: list[str] = []
