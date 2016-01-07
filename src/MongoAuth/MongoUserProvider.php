<?php namespace MongoAuth;

use Illuminate\Auth\GenericUser;
use Illuminate\Auth\UserInterface;
use Illuminate\Auth\UserProviderInterface;
use Illuminate\Hashing\HasherInterface;
use LMongo\Connection;

class MongoUserProvider implements UserProviderInterface {

    /**
     * The database connection instance.
     *
     * @var LMongo\Connection
     */
    protected $connection;

    /**
     * The collection containing the users
     *
     * @var string
     */
    protected $collection;

    /**
     * The hasher implementation.
     *
     * @var Illuminate\Hashing\HasherInterface
     */
    protected $hasher;

    /**
     * Create a new database user provider.
     *
     * @param  LMongo\Connection  $connection
     * @param  Illuminate\Hashing\HasherInterface  $hasher
     * @param  string  $collection
     * @return void
     */
    public function __construct(Connection $connection, HasherInterface $hasher, $collection)
    {
        $this->connection = $connection;
        $this->collection = $collection;
        $this->hasher = $hasher;
    }

	/**
     * Retrieve a user by their unique idenetifier.
     *
     * @param  mixed  $identifier
     * @return Illuminate\Auth\UserInterface|null
     */
    public function retrieveByID($identifier)
    {
        $user = $this->connection->collection($this->collection)->find($identifier);

        if ( ! is_null($user))
        {
            $user['id'] = (string) $user['_id'];

            return new GenericUser((array) $user);
        }
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @TODO Get rid of hardcoded password attribute
     *
     * @param  array  $credentials
     * @return Illuminate\Auth\UserInterface|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        $query = $this->connection->collection($this->collection);

        foreach ($credentials as $key => $value)
        {
            if ( ! str_contains($key, 'Password'))
            {
                $query->where($key, $value);
            }
        }

        $user = $query->first();

        if ( ! is_null($user))
        {
            $user['id'] = (string) $user['_id'];
            $user['password'] = $user['Password'];

            return new GenericUser((array) $user);
        }
    }

    /**
     * Validate a user against the given credentials.
     *
     * @TODO Get rid of hardcoded password attribute
     * @TODO Credentials check has been changed for backward compatibility. Fix this
     *
     * @param  Illuminate\Auth\UserInterface  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(UserInterface $user, array $credentials)
    {
        $plain = $credentials['Password'];
        $salt  = $user->PasswordSalt;
        $hash  = crypt(sha1($plain), $salt);

        return ($user->getAuthPassword() == $hash);
    }

    /**
     * Retrieve a user by by their unique identifier and "remember me" token.
     *
     * @param  mixed $identifier
     * @param  string $token
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveByToken($identifier, $token)
    {
        $user = $this->connection->collection($this->collection)->find($identifier);

        return ($token == $user->getRememberTokenName()) ? $user : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Auth\UserInterface $user
     * @param  string $token
     * @return void
     */
    public function updateRememberToken(UserInterface $user, $token)
    {
        $user->setAttribute($user->getRememberTokenName(), $token);

        $user->save();
    }
}