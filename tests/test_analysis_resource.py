from reccmp.isledecomp.formats import NEImage
from reccmp.isledecomp.analysis.resource import WinResourceType, ne_resource_table


def test_resources(skifree: NEImage):
    resources = list(ne_resource_table(skifree))
    bitmaps = [r for r in resources if r.type == WinResourceType.RT_BITMAP]
    assert len(bitmaps) == 86
