#!/usr/bin/env python

# Copyright 2019, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""Tool for verifying VBMeta & calculate VBMeta Digests of Pixel factory images.

If given an HTTPS URL it will download the file first before processing.
$ pixel_factory_image_verify.py https://dl.google.com/dl/android/aosp/image.zip

Otherwise, the argument is considered to be a local file.
$ pixel_factory_image_verify.py image.zip

The list of canonical Pixel factory images can be found here:
https://developers.google.com/android/images

Supported are all factory images of Pixel 3 and later devices.

In order for the tool to run correct the following utilities need to be
pre-installed: wget, unzip.

The tool also runs outside of the repository location as long as the working
directory is writable.
"""

from __future__ import print_function

import os
import shutil
import subprocess
import sys
import tempfile
import distutils.spawn


class PixelFactoryImageVerifier(object):
  """Object for the pixel_factory_image_verify command line tool."""

  def __init__(self):
    self.working_dir = os.getcwd()
    self.script_path = os.path.realpath(__file__)
    self.script_dir = os.path.split(self.script_path)[0]
    self.avbtool_path = os.path.abspath(os.path.join(self.script_path,
                                                     '../../../avbtool'))

  def run(self, argv):
    """Command line processor.

    Args:
       argv: The command line parameter list.
    """
    # Checks for command line parameters and show help if non given.
    if len(argv) != 2:
      print('No command line parameter given. At least a filename or URL for a '
            'Pixel 3 or later factory image needs to be specified.')
      sys.exit(1)

    # Checks if necessary commands are available.
    for cmd in ['grep', 'unzip', 'wget']:
      if not distutils.spawn.find_executable(cmd):
        print('Necessary command line tool needs to be installed first: %s'
              % cmd)
        sys.exit(1)

    # Downloads factory image if URL is specified; otherwise treat it as file.
    if argv[1].lower().startswith('https://'):
      factory_image_zip = self._download_factory_image(argv[1])
      if not factory_image_zip:
        sys.exit(1)
    else:
      factory_image_zip = os.path.abspath(argv[1])

    # Unpacks the factory image into partition images.
    partition_image_dir = self._unpack_factory_image(factory_image_zip)
    if not partition_image_dir:
      sys.exit(1)

    # Validates the VBMeta of the factory image.
    verified = self._verify_vbmeta_partitions(partition_image_dir)
    if not verified:
      sys.exit(1)

    fingerprint = self._extract_build_fingerprint(partition_image_dir)
    if not fingerprint:
      sys.exit(1)

    # Calculates the VBMeta Digest for the factory image.
    vbmeta_digest = self._calculate_vbmeta_digest(partition_image_dir)
    if not vbmeta_digest:
      sys.exit(1)

    print('The build fingerprint for factory image is: %s' % fingerprint)
    print('The VBMeta Digest for factory image is: %s' % vbmeta_digest)
    sys.exit(0)

  def _download_factory_image(self, url):
    """Downloads the factory image to the working directory.

    Args:
      url: The download URL for the factory image.

    Returns:
      The absolute path to the factory image or None if it failed.
    """
    # Creates temporary download folder.
    download_path = tempfile.mkdtemp(dir=self.working_dir)

    # Downloads the factory image to the temporary folder.
    download_filename = self._download_file(download_path, url)
    if not download_filename:
      return None

    # Moves the downloaded file into the working directory.
    download_file = os.path.join(download_path, download_filename)
    target_file = os.path.join(self.working_dir, download_filename)
    if os.path.exists(target_file):
      try:
        os.remove(target_file)
      except OSError as e:
        print('File %s already exists and cannot be deleted.' % download_file)
        return None
    try:
      shutil.move(download_file, self.working_dir)
    except shutil.Error as e:
      print('File %s cannot be moved to %s: %s' % (download_file,
                                                   target_file, e))
      return None

    # Removes temporary download folder.
    try:
      shutil.rmtree(download_path)
    except shutil.Error as e:
      print('Temporary download folder %s could not be removed.'
            % download_path)
    return os.path.join(self.working_dir, download_filename)

  def _download_file(self, download_dir, url):
    """Downloads a file from the Internet.

    Args:
      download_dir: The folder the file should be downloaded to.
      url: The download URL for the file.

    Returns:
      The name of the downloaded file as it apears on disk; otherwise None
      if download failed.
    """
    print('Fetching file from: %s' % url)
    os.chdir(download_dir)
    args = ['wget', url]
    result, _ = self._run_command(args,
                                  'Successfully downloaded file.',
                                  'File download failed.')
    os.chdir(self.working_dir)
    if not result:
      return None

    # Figure out the file name of what was downloaded: It will be the only file
    # in the download folder.
    files = os.listdir(download_dir)
    if files and len(files) == 1:
      return files[0]
    else:
      return None

  def _unpack_factory_image(self, factory_image_file):
    """Unpacks the factory image zip file.

    Args:
      factory_image_file: path and file name to the image file.

    Returns:
      The path to the folder which contains the unpacked factory image files or
      None if it failed.
    """
    unpack_dir = tempfile.mkdtemp(dir=self.working_dir)
    args = ['unzip', factory_image_file, '-d', unpack_dir]
    result, _ = self._run_command(args,
                                  'Successfully unpacked factory image.',
                                  'Failed to unpack factory image.')
    if not result:
      return None

    # Locate the directory which contains the image files.
    files = os.listdir(unpack_dir)
    image_name = None
    for f in files:
      path = os.path.join(self.working_dir, unpack_dir, f)
      if os.path.isdir(path):
        image_name = f
        break
    if not image_name:
      print('No image found: %s' % image_name)
      return None

    # Move image file directory to the working directory
    image_dir = os.path.join(unpack_dir, image_name)
    target_dir = os.path.join(self.working_dir, image_name)
    if os.path.exists(target_dir):
      try:
        shutil.rmtree(target_dir)
      except shutil.Error as e:
        print('Directory %s already exists and cannot be deleted.' % target_dir)
        return None

    try:
      shutil.move(image_dir, self.working_dir)
    except shutil.Error as e:
      print('Directory %s could not be moved to %s: %s' % (image_dir,
                                                           self.working_dir, e))
      return None

    # Removes tmp unpack directory.
    try:
      shutil.rmtree(unpack_dir)
    except shutil.Error as e:
      print('Temporary download folder %s could not be removed.'
            % unpack_dir)

    # Unzip the secondary zip file which contain the individual images.
    image_filename = 'image-%s' % image_name
    image_folder = os.path.join(self.working_dir, image_name)
    os.chdir(image_folder)

    args = ['unzip', image_filename]
    result, _ = self._run_command(
        args,
        'Successfully unpacked factory image partitions.',
        'Failed to unpack factory image partitions.')
    if not result:
      return None
    return image_folder

  def _verify_vbmeta_partitions(self, image_dir):
    """Verifies all partitions protected by VBMeta using avbtool verify_image.

    Args:
      image_dir: The folder containing the unpacked factory image partitions,
      which contains a vbmeta.img patition.

    Returns:
      True if the VBMeta protected parititions verify.
    """
    os.chdir(image_dir)
    args = [self.avbtool_path,
            'verify_image',
            '--image', 'vbmeta.img',
            '--follow_chain_partitions']
    result, _ = self._run_command(args,
                                  'Successfully verified VBmeta.',
                                  'Verification of VBmeta failed.')
    os.chdir(self.working_dir)
    return result

  def _extract_build_fingerprint(self, image_dir):
    """Extracts the build fingerprint from the system.img.
    Args:
      image_dir: The folder containing the unpacked factory image partitions,
        which contains a vbmeta.img patition.

    Returns:
      The build fingerprint string, e.g.
      google/blueline/blueline:9/PQ2A.190305.002/5240760:user/release-keys
    """ 
    os.chdir(image_dir)
    args = ['grep',
            '-a',
            'ro\..*build\.fingerprint=google/.*/release-keys',
            'system.img']

    result, output = self._run_command(
        args,
        'Successfully extracted build fingerpint.',
        'Build fingerprint extraction failed.')
    os.chdir(self.working_dir)
    if result:
      _, fingerprint = output.split('=', 1)
      return fingerprint.rstrip()
    else:
      return None

  def _calculate_vbmeta_digest(self, image_dir):
    """Calculates the VBMeta Digest for given parititions using avbtool.

    Args:
      image_dir: The folder containing the unpacked factory image partitions,
        which contains a vbmeta.img partition.

    Returns:
      Hex string with the VBmeta Digest value or None if it failed.
    """
    os.chdir(image_dir)
    args = [self.avbtool_path,
            'calculate_vbmeta_digest',
            '--image', 'vbmeta.img']
    result, output = self._run_command(args,
                                       'Successfully calculated VBMeta Digest.',
                                       'Failed to calculate VBmeta Digest.')
    os.chdir(self.working_dir)
    if result:
      return output
    else:
      return None

  def _run_command(self, args, success_msg, fail_msg):
    """Runs command line tools."""
    p = subprocess.Popen(args, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pout, _ = p.communicate()
    if p.wait() == 0:
      print(success_msg)
      return True, pout
    else:
      print(fail_msg)
      return False, pout


if __name__ == '__main__':
  tool = PixelFactoryImageVerifier()
  tool.run(sys.argv)

