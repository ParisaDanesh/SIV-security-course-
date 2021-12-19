import argparse
from modules import SIV

parser = argparse.ArgumentParser(
    description='SIV (System Integrity Verifier)',
    usage='%(prog)s <-i|-v|-h> –D monitored_directory -V verification_file -R report_file(text file) -H hash_function'
)

# python3.7 main.py -i -D /home/pali/PycharmProjects/SIV/example/monitored_dir/ -V /home/pali/PycharmProjects/SIV/example/verification.txt -R /home/pali/PycharmProjects/SIV/example/report.txt -H md5
# python3.7 main.py -v -D /home/pali/PycharmProjects/SIV/example/monitored_dir/ -V /home/pali/PycharmProjects/SIV/example/verification.txt -R /home/pali/PycharmProjects/SIV/example/report.txt

parser.add_argument('-i',
                    dest='init', action='store_true', help='initialization mode')

parser.add_argument('-v',
                    dest='verification', action='store_true', help='verification mode')

parser.add_argument('-D', action='store', metavar='monitored_directory', required=True,
                    dest='monitored_dir', type=str, help='path to the monitor directory')

parser.add_argument('-V', action='store', metavar='verification_file', required=True,
                    dest='verification_file', type=str, help='path to the verification file')

parser.add_argument('-R', action='store', metavar='report_file', required=True,
                    dest='report_file', type=str, help='path to the report file')

parser.add_argument('-H',
                    dest='hash_func', type=str, help='Hash function in initialization mode, if you use in '
                                                     'verification mode it will be restored from existing '
                                                     'verification file.',
                    choices=['md5', 'sha1'])

args = parser.parse_args()

assert args.init ^ args.verification, 'one of the -i or -v switches should be selected, -i initialization mode, ' \
                                      '-v verification mode '

inputs = dict(
    monitored_dir=args.monitored_dir,
    verification_file=args.verification_file,
    report_file=args.report_file
)


# if it is init mode, add hash function to it
if args.init:
    assert args.hash_func, "For the initialization mode you should determine the hash function using -H switch"

    inputs.update(
        mode='init',
        hash_func=args.hash_func
    )

elif args.verification:
    inputs.update(
        mode='verification'
    )

SIV.SIV(**inputs)
