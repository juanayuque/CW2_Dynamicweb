# wsgi.py

from Source import app as application


#  NB// Replace the 'menuServer' reference with your .py server file name
# 'app' comes from the .py server file (see line 5)
#
# There several different options we could consider for structuring our Flask project
#   to be ready for deployment, but this example is quite simple and easy to implement
#    from what you have been working with locally and the examples you have seen
#     to this point.
#
#  When accessing the COMSC instance of OpenShift you will need the Cardiff University
#    VPN active
#
#  Information for this setup was taken from:
#  - CM1102 Flask Learning Materials, Lab 5, Flask 3, "Website Deployment on OpenShift"
#  - "Openshift - Getting Started With Python", https://www.openshift.com/blog/getting-started-python
#
