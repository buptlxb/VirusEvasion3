#!/usr/bin/env python

import itertools
import mimetools
import mimetypes
import urllib
import urllib2
import json


class MultiPartForm(object):
    """Accumulate the data to be used when posting a form."""

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = mimetools.choose_boundary()
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))
        return

    def add_file(self, fieldname, filename, fileHandle, mimetype=None):
        """Add a file to be uploaded."""
        body = fileHandle.read()
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))
        return

    def __str__(self):
        """Return a string representing the form data, including attached files."""
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.  
        parts = []
        part_boundary = '--' + self.boundary

        # Add the form fields
        parts.extend(
            [part_boundary,
             'Content-Disposition: form-data; name="%s"' % name,
             '',
             value,
            ]
            for name, value in self.form_fields
        )

        # Add the files to upload
        parts.extend(
            [part_boundary,
             'Content-Disposition: file; name="%s"; filename="%s"' % \
             (field_name, filename),
             'Content-Type: %s' % content_type,
             '',
             body,
            ]
            for field_name, filename, content_type, body in self.files
        )

        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)


def scan(apikey, fileHandler):
    form = MultiPartForm()
    form.add_field('apikey', apikey)

    form.add_file('file', 'file.exe', fileHandler)

    # Build the request
    request = urllib2.Request('https://www.virustotal.com/vtapi/v2/file/scan')
    request.add_header('User-agent', 'ICT (http://www.ict.ac.cn)')
    body = str(form)
    request.add_header('Content-type', form.get_content_type())
    request.add_header('Content-length', len(body))
    request.add_data(body)

    response = urllib2.urlopen(request).read()
    res_json = json.loads(response)
    print res_json['verbose_msg']
    return res_json['resource']


def report(apikey, resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    parameters = {'resource': resource, 'apikey': apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    response_data = response.read()
    if response_data == '':
        print 'Nothing received'
        return None
    response_json = json.loads(response_data)
    if response_json['response_code'] == 0:
        print response_json['verbose_msg']
        return None
    return response_json