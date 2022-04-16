import os
import glob2
import random
import pandas as pd


def sample_random_users(features, insiders_df, test_size=0.25, random_state=0):
    all_malicious_users = insiders_df['user'].values
    all_users = features["user"].values

    random.seed(random_state)

    malicious_users = list(set(all_malicious_users).intersection(all_users))
    benign_users = list(set(all_users).difference(malicious_users))

    test_malicious_users = random.sample(malicious_users,
                                         int(len(malicious_users) * test_size))
    test_benign_users = random.sample(benign_users,
                                      int(len(benign_users) * test_size))

    train_malicious_users = list(set(malicious_users).difference(test_malicious_users))
    train_benign_users = list(set(benign_users).difference(test_benign_users))

    train_users = train_benign_users + train_malicious_users
    test_users = test_benign_users + test_malicious_users
    return train_users, test_users


def is_malicious(x , mal_users_events):
    x = list(x)
    user = x[1]
    min_date = x[0]
    max_date = x[0]
    if(user not in mal_users_events):
        return 0
    else:
        user_df = mal_users_events[user]
        mal_events_count = user_df[(user_df['date'] >= min_date) &
                                   (user_df['date'] <= max_date)].shape[0]
        return int(mal_events_count > 0)


def get_user_from_path(path):
    user = path.split('/')[-1].split('.csv')[0].split('-')[-1]
    return user


def read_answer_file(path):
    df = pd.read_csv(path, header=None, usecols=[0,1,2,3,4]).rename(columns={0: 'action',
                                                                            1: 'ID',
                                                                            2: 'date',
                                                                            3: 'user',
                                                                            4: 'pc'})
    df['date'] = pd.to_datetime(df['date'])
    df['day'] = df['date'].dt.date
    return df


def read_malicious_events(answers_dir, dataset_ver=5.2):
    mal_event_paths = glob2.glob(os.path.join(answers_dir, f'r{dataset_ver}-*/*'))
    mal_users = [get_user_from_path(p) for p in mal_event_paths]
    mal_user_events = {user: read_answer_file(path)
                       for (user, path) in zip(mal_users, mal_event_paths)}
    return mal_user_events


def is_malicious_day(x , mal_users_events):
    day = x.day
    user = x.user

    if(user not in mal_users_events):
        return 0
    user_df = mal_users_events[user]
    mal_events_count = user_df[(user_df['day'] == day)].shape[0]
    return int(mal_events_count > 0)