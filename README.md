# ShineNETConfigs

Automated V2Ray configuration scraper and tester that runs on GitHub Actions to collect, test, and maintain a list of working proxy configurations.

## Features

- Scrapes V2Ray configurations from v2nodes.com
- Tests each configuration for connectivity using ping tests
- Automatically updates the configuration list every hour
- Only keeps configurations that pass connectivity tests
- Uses python-v2ray library for configuration parsing and testing

## How It Works

1. **Scraping**: The script scrapes v2nodes.com for V2Ray configurations (vmess, vless, trojan, ss)
2. **Downloading**: Downloads necessary binaries (xray, core_engine, hysteria)
3. **Testing**: Tests each configuration using ping tests through the core_engine tester
4. **Filtering**: Only configurations that pass the connectivity test are saved
5. **Updating**: The configs.txt file is automatically updated every hour via GitHub Actions

## GitHub Actions Workflow

The workflow runs on a schedule (every hour) and performs these steps:

1. Checks out the repository
2. Sets up Python environment
3. Installs dependencies
4. Downloads required binaries
5. Ensures tester executable is available
6. Runs the scraping and testing script
7. Commits and pushes any updates to configs.txt

## File Structure

- `v2ray_mining.py` - Main scraping and testing script
- `configs.txt` - List of working configurations (automatically updated)
- `vendor/` - Downloaded binaries (xray, hysteria)
- `core_engine/` - Core testing engine
- `.github/workflows/scrape.yml` - GitHub Actions workflow

## Usage

The repository is designed to run automatically via GitHub Actions. To run locally:

```bash
python v2ray_mining.py
```

## Requirements

- Python 3.10+
- python-v2ray library
- requests
- beautifulsoup4

Install dependencies:
```bash
pip install requests beautifulsoup4 python-v2ray
```

## Configuration

You can modify the following settings in `v2ray_mining.py`:

- `BASE_URL` - The website to scrape from
- `PAGES_TO_SCRAPE` - Number of pages to scrape
- `REQUEST_TIMEOUT` - Request timeout in seconds

## Troubleshooting

If you encounter "Tester executable not found" errors:

1. Ensure all binaries are downloaded properly
2. Check that the core_engine executable exists in either vendor/ or core_engine/ directories
3. Make sure the tester executable has proper execute permissions

## License

This project is for educational purposes only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.