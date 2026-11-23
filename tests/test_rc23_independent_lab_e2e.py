"""Exercise real FastAPI lab HTTP behavior with owner, other, and protected control."""
from qa.rc23_independent_lab_e2e import run_independent_lab_e2e


def test_real_local_lab_authorization_and_cleanup():
    result=run_independent_lab_e2e()
    assert result['vulnerable_controls_confirmed']==2
    assert result['safe_controls_passed']==1
    assert result['requests_to_external_network']==0
