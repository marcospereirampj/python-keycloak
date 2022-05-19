from keycloak import urls_patterns


def test_correctness_of_patterns():
    """Test that there are no duplicate url patterns."""

    # Test that the patterns are present
    urls = [x for x in dir(urls_patterns) if not x.startswith("__")]
    assert len(urls) >= 0

    # Test that all patterns start with URL_
    for url in urls:
        assert url.startswith("URL_"), f"The url pattern {url} does not begin with URL_"

    # Test that the patterns have unique names
    seen_urls = list()
    for url in urls:
        assert url not in seen_urls, f"The url pattern {url} is present twice."
        seen_urls.append(url)

    # Test that the pattern values are unique
    seen_url_values = list()
    for url in urls:
        url_value = urls_patterns.__dict__[url]
        assert url_value not in seen_url_values, f"The url {url} has a duplicate value {url_value}"
        seen_url_values.append(url_value)
