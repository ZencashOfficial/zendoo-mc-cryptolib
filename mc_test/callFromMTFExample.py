#!/usr/bin/env python2

from itertools import chain
import subprocess
import os.path, os, binascii
import random

def generate_params(params_dir, circuit_type, proving_system_type):
    args = [];
    args.append("./mcTest")
    args.append("generate")
    args.append(str(circuit_type))
    args.append(str(proving_system_type))
    args.append(str(params_dir))
    subprocess.check_call(args)

def cert_proof_test(proof_path, params_dir, ps_type, bt_num, cf_num, zk):

    # Setup SNARK pk and vk
    generate_params(params_dir, "cert", ps_type);

    # Generate random test data
    epoch_number = random.randint(0, 10)
    quality = random.randint(0, 100)
    btr_fee = random.randint(0, 1000)
    ft_min_amount = random.randint(0, 5000)
    constant = generate_random_field_element_hex()
    end_cum_comm_tree_root = generate_random_field_element_hex()
    pks = [binascii.b2a_hex(os.urandom(20)) for i in xrange(bt_num)]
    amounts = [random.randint(0, 100) for i in xrange(bt_num)]
    custom_fields = [generate_random_field_element_hex() for i in xrange(cf_num)]

    # Generate and verify proof
    args = ["./mcTest", "create", "cert", str(ps_type), "-v"]
    if zk:
        args.append("-zk")
    args.append(str(proof_path))
    args.append(str(params_dir))
    args += [str(epoch_number), str(quality), str(constant), str(end_cum_comm_tree_root), str(btr_fee), str(ft_min_amount)]

    args.append(str(bt_num))
    for (pk, amount) in zip(pks, amounts):
        args.append(str(pk))
        args.append(str(amount))

    args.append(str(cf_num))
    for cf in custom_fields:
        args.append(str(cf))

    subprocess.check_call(args)


    # Delete files
    os.remove(proof_path)
    os.remove(params_dir + str(ps_type) + str("_cert_test_pk"))
    os.remove(params_dir + str(ps_type) + str("_cert_test_vk"))

def csw_proof_test(proof_path, params_dir, ps_type, zk):

    # Setup SNARK pk and vk
    generate_params(params_dir, "csw", ps_type);

    # Generate random test data
    amount = random.randint(0, 1000)
    sc_id = generate_random_field_element_hex()
    nullifier = generate_random_field_element_hex()
    mc_pk_hash = binascii.b2a_hex(os.urandom(20))
    end_cum_comm_tree_root = generate_random_field_element_hex()
    cert_data_hash = generate_random_field_element_hex()

    # Generate and verify proof
    args = ["./mcTest", "create", "csw", str(ps_type), "-v"]
    if zk:
        args.append("-zk")
    args.append(str(proof_path))
    args.append(str(params_dir))
    args += [str(amount), str(sc_id), str(nullifier), str(mc_pk_hash), str(end_cum_comm_tree_root), str(cert_data_hash)]
    subprocess.check_call(args)

    # Delete files
    os.remove(proof_path)
    os.remove(params_dir + str(ps_type) + str("_csw_test_pk"))
    os.remove(params_dir + str(ps_type) + str("_csw_test_vk"))


def generate_random_field_element_hex():
    return (binascii.b2a_hex(os.urandom(31)) + "00")

if __name__ == "__main__":

    data_dir = os.getcwd() + "/";

    # Test certificate proof
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 10, True)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 0, True)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 10, False)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 0, False)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 10, True)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 0, True)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 10, False)
    cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 0, False)

    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 10, True)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 0, True)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 10, False)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 0, False)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 10, True)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 0, True)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 10, False)
    cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 0, False)

    # Test csw proof
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", True)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", False)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", True)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", False)

    os.remove(data_dir + str("ck_g1"))
    os.remove(data_dir + str("ck_g2"))