import setuptools


setuptools.setup(
     name='easy-re',  
     version='1',
     scripts=['easy_re'] ,
     author="Christoppher Roberts",
     author_email="",
     description="Use angr to solve RE problems fast",
     url="https://github.com/ChrisTheCoolHut/easy-re",
     packages=setuptools.find_packages(),
     install_requires=[
     "angr",
     "r2pipe",
     ],

 )