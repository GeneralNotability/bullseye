# bullseye
Extended IP info for Wikipedia

## Toolforge
bullseye is hosted on [Wikimedia Toolforge](https://wikitech.wikimedia.org/wiki/Portal:Toolforge) at https://bullseye.toolforge.org

## Running the tool
### Get the repo
```
git clone https://github.com/GeneralNotability/bullseye.git
cd bullseye
```

### Set up a Python virtual environment
```
python -m venv venv
```
*Then [activate](https://docs.python.org/3/library/venv.html) the virtual environment*

### Install the requirements
```
pip install -r requirements.txt
```

### Configure
Create a settings file from the provided `bullseye/settings-example.py`

Don't forget to download `GeoLite2-City.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en) and place it in the project root.

### Run the Django development server
```
python manage.py runserver
```