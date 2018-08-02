import base64
import json

from model.FuzzingTarget import targets
from model.FuzzingJob import fuzz_jobs
from model.FuzzingInputs import inputs
from model.job_inputs import job_inputs
from model.Config import FuzzingConfig
from model.instrumentation_state import instrumentation_state

def listseeds():
    """
    Prints the list of seed funcctions that we accept. Make sure to keep this up to date.
    Having this kept up to date is cleaner than trying to parse the AST or getattr and isfunction.
    :return: Nothing; just prints
    """
    print("The following seed options exist:")
    print("\tclient_request: For testing that a client can request a job successfully. Creates x86 and x86_64")
    print("\t\t jobs that the client get endpoint should be able to find.")

def seed(db, forwhich):
    if forwhich == "client_request":
        client_request(db)
        return True
    return False

def client_request(db):
    #db.session.add(targets(None, "x86", "Windows 10", "test2.exe"))
    #db.session.add(targets(None, "x86", "Windows 8", "test1.exe"))
    #db.session.add(targets(None, "x86_64", "Windows 10", "test2.exe"))
    db.session.add(targets("x86", "CYGWIN_NT-10.0 2.10.0(0.325/5/3)", "test2.exe"))
    db.session.add(targets("x86", "CYGWIN_NT-10.0 2.10.0(0.325/5/3)", "test1.exe"))
    db.session.add(targets("x86_64", "Windows 10", "test2.exe"))
    db.session.add(fuzz_jobs("fuzz", 1, status='assigned'))
    db.session.add(fuzz_jobs("fuzz", 3, mutator='nop', instrumentation_type='dynamorio', driver='wmp'))
    db.session.add(fuzz_jobs("fuzz", 3, mutator='radamsa', instrumentation_type='dynamorio', driver='wmp'))
    db.session.add(fuzz_jobs("fuzz", 2))
    db.session.add(fuzz_jobs("fuzz", 1))
    db.session.add(fuzz_jobs("fuzz", 3, instrumentation_type="testinstrumentor"))
    db.session.add(inputs("AAAAAAAA"))
    db.session.add(inputs("BBBBBBBB"))
    db.session.add(job_inputs(4, 1))
    db.session.add(job_inputs(4, 2))
    # db.session.add(job_inputs(5, 1))
    db.session.add(job_inputs(5, 2))
    db.session.add(job_inputs(2, 2))
    db.session.add(job_inputs(3, 2))
    db.session.add(job_inputs(1, 1))
    db.session.add(job_inputs(6, 1))
    # db.session.add(job_inputs(1, 2))
    db.session.add(FuzzingConfig("instrumentation_opts_testinstrumentor", "testfallbacktarget", target=3))
    db.session.add(FuzzingConfig("driver_opts_stdin", "stdinopts", target=3))
    db.session.add(FuzzingConfig("mutator_opts_radamsa", json.dumps({'seed': 5}), target=3))
    db.session.add(FuzzingConfig("mutator_opts_radamsa", "{radamsoo}", target=2))
    #db.session.add(FuzzingConfig("instrumentation_opts_testinstrumentor", "testfallbackjob", job=6))
    db.session.add(FuzzingConfig('instrumentation_opts_dynamorio', json.dumps({
        "per_module_coverage": 1,
        "timeout": 10000,
        "coverage_modules": ["wmp.DLL"],
        "client_params": "-target_module wmplayer.exe -target_offset 0x1F20 -nargs 3",
        "fuzz_iterations":1,
        "target_path": "C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe"
    }), target=3))
    db.session.commit()
