# Copyright 2023 Volvo Car Corporation
# This file is covered by LICENSE file in the root of this project

import os
import sys

# This is needed due to protobuf generated files which import local python modules
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
