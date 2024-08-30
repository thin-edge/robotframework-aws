"""Random data generator"""

import randomname


def random_name() -> str:
    """Provide a random name."""
    return RandomNameGenerator.random_name()


class RandomNameGenerator:
    """Provides randomly generated names using a public service."""

    # pylint: disable=too-few-public-methods

    @classmethod
    def random_name(cls, num: int = 3, sep: str = "_") -> str:
        """Generate a readable random name from joined random words.
        Args:
            num (int):  number of random words to concatenate
            sep (str):  concatenation separator
        Returns:
            The generated name
        """
        groups = []
        if num <= 1:
            # only a noun
            groups.append("n/")
        elif num == 2:
            # adjective + noun
            groups.append("a/")
            groups.append("n/")
        else:
            # one verb
            groups.append("v/")

            # use adjectives in between
            groups.extend(["a/"] * (num - 2))

            # then one noun
            groups.append("n/")

        return randomname.generate(*groups, sep=sep)
